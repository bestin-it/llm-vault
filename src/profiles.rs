//! Local user profiles ("sign in to the app").
//!
//! Signing in and unlocking the vault are two independent states (see the product concept):
//! * a **profile** has a user name and an application password (Argon2id hash in profiles.json)
//!   and owns its own data folder: vault file(s), audit database and UI settings;
//! * the **vault** is unlocked separately with the KDBX master password.
//!
//! The profile password protects access to the app and keeps several people / roles on one
//! machine apart. Secrets themselves are protected by the vault encryption, not by this file.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::config::{new_id, now_rfc3339};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    pub created_at: String,
    #[serde(default)]
    pub last_login: Option<String>,
    #[serde(default)]
    pub failed_logins: u32,
}

impl Profile {
    pub fn label(&self) -> String {
        if self.display_name.trim().is_empty() { self.username.clone() } else { format!("{} ({})", self.display_name, self.username) }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProfileStore {
    #[serde(skip)]
    file: PathBuf,
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub last_username: Option<String>,
}

fn argon_config() -> argon2::Config<'static> {
    argon2::Config { variant: argon2::Variant::Argon2id, version: argon2::Version::Version13, mem_cost: 19 * 1024, time_cost: 2, lanes: 1, ..Default::default() }
}

pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    argon2::hash_encoded(password.as_bytes(), &salt, &argon_config()).map_err(|e| anyhow!("hashing failed: {e}"))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    argon2::verify_encoded(hash, password.as_bytes()).unwrap_or(false)
}

pub fn valid_username(u: &str) -> bool {
    let u = u.trim();
    (2..=40).contains(&u.len()) && u.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
}

impl ProfileStore {
    pub fn load(config_dir: &Path) -> Self {
        let file = config_dir.join("profiles.json");
        let mut s: ProfileStore = std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        s.file = file;
        s
    }

    pub fn save(&self) -> Result<()> {
        if let Some(d) = self.file.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = self.file.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(tmp, &self.file)?;
        Ok(())
    }

    pub fn find(&self, username: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.username.eq_ignore_ascii_case(username.trim()))
    }

    pub fn create(&mut self, username: &str, display_name: &str, password: &str) -> Result<Profile> {
        let username = username.trim();
        if !valid_username(username) {
            bail!("user name: 2-40 characters, letters, digits and . _ - @");
        }
        if self.find(username).is_some() {
            bail!("a profile named '{username}' already exists");
        }
        if password.chars().count() < 8 {
            bail!("the login password must have at least 8 characters");
        }
        let p = Profile {
            id: new_id(),
            username: username.to_string(),
            display_name: display_name.trim().to_string(),
            password_hash: hash_password(password)?,
            created_at: now_rfc3339(),
            last_login: None,
            failed_logins: 0,
        };
        self.profiles.push(p.clone());
        self.save()?;
        Ok(p)
    }

    /// Verify credentials. Failed attempts are counted and slowed down.
    pub fn login(&mut self, username: &str, password: &str) -> Result<Profile> {
        let idx = self.profiles.iter().position(|p| p.username.eq_ignore_ascii_case(username.trim()));
        let Some(i) = idx else {
            // same work factor as a real check, so user names cannot be probed by timing
            let _ = verify_password("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password);
            bail!("unknown user name or wrong password");
        };
        if !verify_password(&self.profiles[i].password_hash, password) {
            self.profiles[i].failed_logins += 1;
            let n = self.profiles[i].failed_logins;
            let _ = self.save();
            std::thread::sleep(std::time::Duration::from_millis(400 * n.min(10) as u64));
            bail!("unknown user name or wrong password");
        }
        self.profiles[i].failed_logins = 0;
        self.profiles[i].last_login = Some(now_rfc3339());
        self.last_username = Some(self.profiles[i].username.clone());
        self.save()?;
        Ok(self.profiles[i].clone())
    }

    pub fn change_password(&mut self, username: &str, current: &str, new_password: &str) -> Result<()> {
        let p = self.profiles.iter_mut().find(|p| p.username.eq_ignore_ascii_case(username)).ok_or_else(|| anyhow!("profile not found"))?;
        if !verify_password(&p.password_hash, current) {
            bail!("current login password is incorrect");
        }
        if new_password.chars().count() < 8 {
            bail!("the login password must have at least 8 characters");
        }
        p.password_hash = hash_password(new_password)?;
        self.save()
    }

    /// Remove a profile. There is deliberately no password reset: a user who forgot the
    /// login password can only delete the profile and create a new one.
    pub fn delete(&mut self, username: &str) -> Result<Profile> {
        let idx = self.profiles.iter().position(|p| p.username.eq_ignore_ascii_case(username.trim())).ok_or_else(|| anyhow!("profile not found"))?;
        let p = self.profiles.remove(idx);
        if self.last_username.as_deref().map(|u| u.eq_ignore_ascii_case(&p.username)).unwrap_or(false) {
            self.last_username = None;
        }
        self.save()?;
        Ok(p)
    }

    /// Folder that holds everything belonging to a profile.
    pub fn profile_dir(data_dir: &Path, profile: &Profile) -> PathBuf {
        data_dir.join("profiles").join(&profile.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_login_and_change_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ProfileStore::load(dir.path());
        s.create("artur", "Artur", "first-password").unwrap();
        assert!(s.create("ARTUR", "", "another-password").is_err(), "user names are case-insensitive");
        assert!(s.create("x y", "", "another-password").is_err());
        let mut s = ProfileStore::load(dir.path());
        assert!(s.login("artur", "wrong-password").is_err());
        assert_eq!(s.find("artur").unwrap().failed_logins, 1);
        assert!(s.login("Artur", "first-password").is_ok());
        assert_eq!(s.find("artur").unwrap().failed_logins, 0);
        s.change_password("artur", "first-password", "second-password").unwrap();
        assert!(s.login("artur", "second-password").is_ok());
        assert!(s.login("nobody", "second-password").is_err());
        let raw = std::fs::read_to_string(dir.path().join("profiles.json")).unwrap();
        assert!(!raw.contains("second-password") && raw.contains("$argon2id$"));
    }
}
