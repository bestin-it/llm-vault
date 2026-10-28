//! KeePass-compatible encrypted vault (KDBX 4.1).
//!
//! * Outer encryption: AES-256-CBC, HMAC-SHA-256 block integrity (KDBX 4 standard).
//! * Key derivation: Argon2id (64 MiB, tuned iterations).
//! * Protected fields (passwords, API keys) are additionally encrypted inside the XML with
//!   ChaCha20 and are held in memory as zeroize-on-drop secrets.
//! * The file opens in KeePass, KeePassXC, KeePassDX, Strongbox... and LLM Vault opens existing
//!   KeePass databases.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::{CustomDataItem, CustomDataValue, EntryId, GroupId, Times, fields};
use keepass::{Database, DatabaseKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{CONFIG_CUSTOM_DATA_KEY, VaultConfig};

pub const PROVIDER_GROUP: &str = "LLM Providers";
pub const PROVIDER_TAG: &str = "llmvault-provider";

/// Argon2id cost parameters. `Standard` is used for real vaults, `Fast` only in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfStrength {
    Standard,
    Fast,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub depth: i32,
    pub entry_count: i32,
    pub is_provider_group: bool,
}

/// Entry metadata shown in lists. Never contains the password.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntryInfo {
    pub id: String,
    pub group_id: String,
    pub group_name: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub has_password: bool,
    pub is_provider_key: bool,
    pub modified: String,
    pub expires: String,
}

/// Data submitted by the entry editor.
#[derive(Debug, Clone, Default)]
pub struct EntryInput {
    pub id: Option<String>,
    pub group_id: Option<String>,
    pub title: String,
    pub username: String,
    /// None = keep the existing password.
    pub password: Option<Zeroizing<String>>,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub expires: Option<chrono::NaiveDate>,
}

pub struct Vault {
    path: PathBuf,
    keyfile: Option<PathBuf>,
    key: DatabaseKey,
    db: Database,
    pub config: VaultConfig,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("path", &self.path).finish_non_exhaustive()
    }
}

fn kdf_for(strength: KdfStrength) -> KdfConfig {
    match strength {
        KdfStrength::Standard => KdfConfig::Argon2id {
            iterations: 5,
            memory: 64 * 1024 * 1024,
            parallelism: 4,
            version: argon2::Version::Version13,
        },
        KdfStrength::Fast => KdfConfig::Argon2id {
            iterations: 1,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        },
    }
}

fn build_key(password: &str, keyfile: Option<&Path>) -> Result<DatabaseKey> {
    let mut key = DatabaseKey::new().with_password(password);
    if let Some(kf) = keyfile {
        let mut f = fs::File::open(kf).with_context(|| format!("cannot open key file {}", kf.display()))?;
        key = key.with_keyfile(&mut f)?;
    }
    Ok(key)
}

fn parse_uuid(id: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(id).map_err(|_| anyhow!("invalid id"))
}

fn fmt_time(t: Option<chrono::NaiveDateTime>) -> String {
    t.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
}

impl Vault {
    /// Create a new, empty vault file. Fails if the file already exists.
    pub fn create(path: &Path, password: &str, keyfile: Option<&Path>, strength: KdfStrength) -> Result<Self> {
        if path.exists() {
            bail!("a file already exists at {}", path.display());
        }
        if password.chars().count() < 8 && keyfile.is_none() {
            bail!("the master password must have at least 8 characters");
        }
        let mut cfg = DatabaseConfig::default();
        cfg.kdf_config = kdf_for(strength);
        let mut db = Database::with_config(cfg);
        db.meta.database_name = Some("LLM Vault".into());
        db.meta.generator = Some(format!("LLM Vault {}", env!("CARGO_PKG_VERSION")));
        db.meta.recyclebin_enabled = Some(false);
        {
            let mut root = db.root_mut();
            root.name = "LLM Vault".into();
        }
        for name in ["General", "Email", "Internet", "Servers & SSH", PROVIDER_GROUP] {
            let mut root = db.root_mut();
            let mut g = root.add_group();
            g.name = name.into();
        }
        let mut vault = Vault { path: path.to_path_buf(), keyfile: keyfile.map(Path::to_path_buf), key: build_key(password, keyfile)?, db, config: VaultConfig::default() };
        crate::providers::seed_default_config(&mut vault.config);
        vault.save()?;
        Ok(vault)
    }

    /// Open (unlock) an existing KDBX file - an LLM Vault file or any KeePass 2.x database.
    pub fn open(path: &Path, password: &str, keyfile: Option<&Path>) -> Result<Self> {
        let key = build_key(password, keyfile)?;
        let mut f = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let db = Database::open(&mut f, key.clone()).map_err(|e| {
            let msg = e.to_string();
            if msg.to_lowercase().contains("key") || msg.to_lowercase().contains("hmac") {
                anyhow!("wrong master password or key file")
            } else {
                anyhow!("cannot open vault: {msg}")
            }
        })?;
        let config = match db.meta.custom_data.get(CONFIG_CUSTOM_DATA_KEY).and_then(|i| i.value.as_ref()) {
            Some(CustomDataValue::String(s)) => serde_json::from_str(s).context("vault configuration is corrupted")?,
            _ => {
                let mut c = VaultConfig::default();
                crate::providers::seed_default_config(&mut c);
                c
            }
        };
        Ok(Vault { path: path.to_path_buf(), keyfile: keyfile.map(Path::to_path_buf), key, db, config })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn name(&self) -> String {
        self.db.meta.database_name.clone().unwrap_or_else(|| "LLM Vault".into())
    }

    /// Persist the database atomically (temp file + rename, previous version kept as .bak).
    pub fn save(&mut self) -> Result<()> {
        let json = serde_json::to_string(&self.config)?;
        self.db.meta.custom_data.insert(
            CONFIG_CUSTOM_DATA_KEY.to_string(),
            CustomDataItem { value: Some(CustomDataValue::String(json)), last_modification_time: Some(Times::now()) },
        );
        let mut buf = Vec::new();
        self.db.save(&mut buf, self.key.clone()).map_err(|e| anyhow!("cannot encrypt vault: {e}"))?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("kdbx.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        if self.path.exists() {
            let _ = fs::copy(&self.path, self.path.with_extension("kdbx.bak"));
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn change_master_password(&mut self, current: &str, new_password: &str) -> Result<()> {
        // Verify the current password by re-opening the file.
        let mut f = fs::File::open(&self.path)?;
        Database::open(&mut f, build_key(current, self.keyfile.as_deref())?).map_err(|_| anyhow!("current password is incorrect"))?;
        if new_password.chars().count() < 8 {
            bail!("the new master password must have at least 8 characters");
        }
        self.key = build_key(new_password, self.keyfile.as_deref())?;
        self.save()
    }

    /// Re-check the master password (used before sensitive operations).
    pub fn verify_password(&self, password: &str) -> bool {
        match fs::File::open(&self.path) {
            Ok(mut f) => match build_key(password, self.keyfile.as_deref()) {
                Ok(k) => Database::open(&mut f, k).is_ok(),
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    // ------------------------------------------------------------------ groups

    pub fn groups(&self) -> Vec<GroupInfo> {
        let mut out = Vec::new();
        fn walk(g: keepass::db::GroupRef<'_>, depth: i32, out: &mut Vec<GroupInfo>) {
            out.push(GroupInfo {
                id: g.id().uuid().to_string(),
                name: if g.name.is_empty() { "(unnamed)".into() } else { g.name.clone() },
                depth,
                entry_count: g.entries().count() as i32,
                is_provider_group: g.name == PROVIDER_GROUP,
            });
            let mut children: Vec<_> = g.groups().collect();
            children.sort_by_key(|c| c.name.to_lowercase());
            for c in children {
                walk(c, depth + 1, out);
            }
        }
        walk(self.db.root(), 0, &mut out);
        out
    }

    pub fn add_group(&mut self, parent: Option<&str>, name: &str) -> Result<String> {
        let name = name.trim();
        if name.is_empty() {
            bail!("group name cannot be empty");
        }
        let parent_id = match parent {
            Some(p) => GroupId::from_uuid(parse_uuid(p)?),
            None => self.db.root().id(),
        };
        let mut parent = self.db.group_mut(parent_id).ok_or_else(|| anyhow!("parent group not found"))?;
        let mut g = parent.add_group();
        g.name = name.to_string();
        let id = g.id().uuid().to_string();
        self.save()?;
        Ok(id)
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<()> {
        let gid = GroupId::from_uuid(parse_uuid(id)?);
        let mut g = self.db.group_mut(gid).ok_or_else(|| anyhow!("group not found"))?;
        if g.name == PROVIDER_GROUP {
            bail!("the '{PROVIDER_GROUP}' group is managed by LLM Vault");
        }
        g.name = name.trim().to_string();
        self.save()
    }

    pub fn delete_group(&mut self, id: &str) -> Result<()> {
        let gid = GroupId::from_uuid(parse_uuid(id)?);
        if gid == self.db.root().id() {
            bail!("the root group cannot be deleted");
        }
        let g = self.db.group(gid).ok_or_else(|| anyhow!("group not found"))?;
        if g.name == PROVIDER_GROUP {
            bail!("the '{PROVIDER_GROUP}' group is managed by LLM Vault");
        }
        if g.entries().count() > 0 || g.groups().count() > 0 {
            bail!("only empty groups can be deleted");
        }
        self.db.group_mut(gid).unwrap().remove();
        self.save()
    }

    fn provider_group_id(&mut self) -> GroupId {
        if let Some(g) = self.db.root().group_by_name(PROVIDER_GROUP) {
            return g.id();
        }
        let mut root = self.db.root_mut();
        let mut g = root.add_group();
        g.name = PROVIDER_GROUP.into();
        g.id()
    }

    // ----------------------------------------------------------------- entries

    fn entry_info(&self, e: keepass::db::EntryRef<'_>) -> EntryInfo {
        let parent = e.parent();
        EntryInfo {
            id: e.id().uuid().to_string(),
            group_id: parent.id().uuid().to_string(),
            group_name: parent.name.clone(),
            title: e.get_title().unwrap_or("").to_string(),
            username: e.get_username().unwrap_or("").to_string(),
            url: e.get_url().unwrap_or("").to_string(),
            notes: e.get(fields::NOTES).unwrap_or("").to_string(),
            tags: e.tags.join(", "),
            has_password: e.get_password().map(|p| !p.is_empty()).unwrap_or(false),
            is_provider_key: e.tags.iter().any(|t| t == PROVIDER_TAG),
            modified: fmt_time(e.times.last_modification),
            expires: if e.times.expires.unwrap_or(false) { e.times.expiry.format("%Y-%m-%d").to_string() } else { String::new() },
        }
    }

    /// List entries in a group (or all groups when `group` is None) matching `search`.
    pub fn entries(&self, group: Option<&str>, search: &str) -> Vec<EntryInfo> {
        let q = search.trim().to_lowercase();
        let group_id = group.and_then(|g| uuid::Uuid::parse_str(g).ok()).map(GroupId::from_uuid);
        let mut out: Vec<EntryInfo> = self
            .db
            .iter_all_entries()
            .filter(|e| group_id.is_none() || Some(e.parent().id()) == group_id)
            .map(|e| self.entry_info(e))
            .filter(|i| {
                q.is_empty()
                    || i.title.to_lowercase().contains(&q)
                    || i.username.to_lowercase().contains(&q)
                    || i.url.to_lowercase().contains(&q)
                    || i.tags.to_lowercase().contains(&q)
                    || i.notes.to_lowercase().contains(&q)
            })
            .collect();
        out.sort_by_key(|i| i.title.to_lowercase());
        out
    }

    pub fn entry(&self, id: &str) -> Option<EntryInfo> {
        let eid = EntryId::from_uuid(uuid::Uuid::parse_str(id).ok()?);
        self.db.entry(eid).map(|e| self.entry_info(e))
    }

    /// Reveal an entry password to the *desktop owner* (copy / show in the UI).
    /// Not reachable from the gateway.
    pub fn entry_password(&self, id: &str) -> Option<Zeroizing<String>> {
        let eid = EntryId::from_uuid(uuid::Uuid::parse_str(id).ok()?);
        self.db.entry(eid).and_then(|e| e.get_password().map(|p| Zeroizing::new(p.to_string())))
    }

    pub fn upsert_entry(&mut self, input: EntryInput) -> Result<String> {
        if input.title.trim().is_empty() {
            bail!("title is required");
        }
        let eid = match &input.id {
            Some(id) if !id.is_empty() => {
                let eid = EntryId::from_uuid(parse_uuid(id)?);
                if self.db.entry(eid).is_none() {
                    bail!("entry not found");
                }
                eid
            }
            _ => {
                let gid = match input.group_id.as_deref().filter(|s| !s.is_empty()) {
                    Some(g) => GroupId::from_uuid(parse_uuid(g)?),
                    None => self.db.root().group_by_name("General").map(|g| g.id()).unwrap_or(self.db.root().id()),
                };
                let mut g = self.db.group_mut(gid).ok_or_else(|| anyhow!("group not found"))?;
                g.add_entry().id()
            }
        };
        let target_group = input.group_id.as_deref().filter(|s| !s.is_empty()).map(parse_uuid).transpose()?;
        let mut e = self.db.entry_mut(eid).unwrap();
        e.set_unprotected(fields::TITLE, input.title.trim());
        e.set_unprotected(fields::USERNAME, input.username.as_str());
        e.set_unprotected(fields::URL, input.url.trim());
        e.set_unprotected(fields::NOTES, input.notes.as_str());
        if let Some(p) = &input.password {
            e.set_protected(fields::PASSWORD, p.as_str());
        } else if e.get_password().is_none() {
            e.set_protected(fields::PASSWORD, "");
        }
        let keep_provider = e.tags.iter().any(|t| t == PROVIDER_TAG);
        e.tags = input.tags.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty() && t != PROVIDER_TAG).collect();
        if keep_provider {
            e.tags.push(PROVIDER_TAG.into());
        }
        match input.expires {
            Some(d) => {
                e.times.expires = Some(true);
                e.times.expiry = d.and_hms_opt(23, 59, 59).unwrap();
            }
            None => e.times.expires = Some(false),
        }
        e.times.last_modification = Some(Times::now());
        if let Some(g) = target_group {
            let gid = GroupId::from_uuid(g);
            if e.as_ref().parent().id() != gid {
                e.move_to(gid).map_err(|_| anyhow!("target group not found"))?;
            }
        }
        self.save()?;
        Ok(eid.uuid().to_string())
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<()> {
        let eid = EntryId::from_uuid(parse_uuid(id)?);
        let e = self.db.entry(eid).ok_or_else(|| anyhow!("entry not found"))?;
        if e.tags.iter().any(|t| t == PROVIDER_TAG) && self.config.providers.iter().any(|p| p.secret_entry.as_deref() == Some(id)) {
            bail!("this key is used by a provider connection - remove the provider first");
        }
        self.db.entry_mut(eid).unwrap().remove();
        self.save()
    }

    // ------------------------------------------------------- provider secrets

    /// Store (or rotate) a provider API key in the "LLM Providers" group. Returns the entry UUID.
    pub fn set_provider_secret(&mut self, existing: Option<&str>, title: &str, url: &str, secret: &str) -> Result<String> {
        let existing_id = existing.and_then(|s| uuid::Uuid::parse_str(s).ok()).map(EntryId::from_uuid).filter(|id| self.db.entry(*id).is_some());
        let eid = match existing_id {
            Some(id) => id,
            None => {
                let gid = self.provider_group_id();
                let mut g = self.db.group_mut(gid).unwrap();
                g.add_entry().id()
            }
        };
        let mut e = self.db.entry_mut(eid).unwrap();
        e.set_unprotected(fields::TITLE, title);
        e.set_unprotected(fields::URL, url);
        e.set_unprotected(fields::USERNAME, "api-key");
        if existing_id.is_none() || !secret.is_empty() {
            e.set_protected(fields::PASSWORD, secret);
        }
        if !e.tags.iter().any(|t| t == PROVIDER_TAG) {
            e.tags.push(PROVIDER_TAG.into());
        }
        e.set_unprotected(
            fields::NOTES,
            "Managed by LLM Vault. This key is used by the gateway and is never returned to API clients or AI agents.",
        );
        e.times.last_modification = Some(Times::now());
        self.save()?;
        Ok(eid.uuid().to_string())
    }

    /// Resolve a provider secret for an outbound call. Crate-private: there is deliberately
    /// no public path from the gateway's client API to this function's return value.
    pub(crate) fn provider_secret(&self, entry_id: &str) -> Option<Zeroizing<String>> {
        let eid = EntryId::from_uuid(uuid::Uuid::parse_str(entry_id).ok()?);
        let e = self.db.entry(eid)?;
        e.get_password().filter(|p| !p.is_empty()).map(|p| Zeroizing::new(p.to_string()))
    }

    /// All provider secrets currently configured - used only to build the log redactor.
    pub(crate) fn provider_secrets(&self) -> Vec<Zeroizing<String>> {
        self.config.providers.iter().filter_map(|p| p.secret_entry.as_deref()).filter_map(|id| self.provider_secret(id)).collect()
    }

    /// Import all entries from another KeePass database into a new group.
    pub fn import_kdbx(&mut self, path: &Path, password: &str, keyfile: Option<&Path>) -> Result<usize> {
        let other = Vault::open(path, password, keyfile)?;
        let group_name = format!(
            "Imported - {}",
            path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "KeePass".into())
        );
        let gid = {
            let mut root = self.db.root_mut();
            let mut g = root.add_group();
            g.name = group_name;
            g.id()
        };
        let mut n = 0;
        for e in other.db.iter_all_entries() {
            let mut g = self.db.group_mut(gid).unwrap();
            let mut ne = g.add_entry();
            for (k, v) in e.fields.iter() {
                ne.set(k.clone(), v.clone());
            }
            ne.tags = e.tags.clone();
            ne.times = e.times.clone();
            n += 1;
        }
        self.save()?;
        Ok(n)
    }

    /// Write a copy of the vault to another location (same password).
    pub fn export_copy(&self, dest: &Path) -> Result<()> {
        let mut buf = Vec::new();
        self.db.save(&mut buf, self.key.clone()).map_err(|e| anyhow!("{e}"))?;
        fs::write(dest, buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_vault_needs_keyfile_and_keeps_it_on_password_change() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("vault.keyx");
        fs::write(&kf, b"0123456789abcdef0123456789abcdef-key-file-content").unwrap();
        let p = dir.path().join("k.kdbx");
        let mut v = Vault::create(&p, "first-password", Some(&kf), KdfStrength::Fast).unwrap();
        assert!(Vault::open(&p, "first-password", None).is_err(), "key file must be required");
        v.change_master_password("first-password", "second-password").unwrap();
        drop(v);
        assert!(Vault::open(&p, "second-password", Some(&kf)).is_ok());
        assert!(Vault::open(&p, "second-password", None).is_err());
    }
}

/// Generate a random password.
pub fn generate_password(length: usize, upper: bool, digits: bool, symbols: bool) -> String {
    use rand::RngExt;
    let mut sets: Vec<&[u8]> = vec![b"abcdefghijkmnopqrstuvwxyz"];
    if upper {
        sets.push(b"ABCDEFGHJKLMNPQRSTUVWXYZ");
    }
    if digits {
        sets.push(b"23456789");
    }
    if symbols {
        sets.push(b"!@#$%^&*()-_=+[]{};:,.?");
    }
    let all: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
    let length = length.clamp(8, 128);
    let mut rng = rand::rng();
    loop {
        let pw: Vec<u8> = (0..length).map(|_| all[rng.random_range(0..all.len())]).collect();
        // ensure every selected class is represented
        if sets.iter().all(|s| pw.iter().any(|c| s.contains(c))) {
            return String::from_utf8(pw).unwrap();
        }
    }
}

/// Rough password strength estimate in bits.
pub fn password_entropy_bits(pw: &str) -> f64 {
    let mut pool = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }
    if pool == 0 {
        return 0.0;
    }
    pw.chars().count() as f64 * (pool as f64).log2()
}
