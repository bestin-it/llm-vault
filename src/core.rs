//! Application core shared by the desktop UI and the gateway.
//!
//! Trust boundary: the desktop UI calls `Core` in-process. The only network surface is the
//! gateway (see `gateway.rs`), which can *use* provider keys on behalf of authorized clients
//! but has no operation that returns a key, a password or any vault entry.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use tokio::sync::oneshot;

use crate::audit::{Audit, RequestRecord};
use crate::config::{ClientConfig, ConsentMode, ConsentRule, ModelAlias, PriceVersion, ProviderConfig, new_id, now_rfc3339};
use crate::paths::{AppSettings, Paths};
use crate::profiles::{Profile, ProfileStore};
use crate::policy::{ConsentDecision, Denial, RateLimiter, hash_token};
use crate::pricing;
use crate::providers::{self, Upstream};
use crate::redact::Redactor;
use crate::vault::{KdfStrength, Vault};

#[derive(Debug, Clone)]
pub enum UiEvent {
    ConsentRequested(ConsentInfo),
    ConsentClosed(String),
    RequestFinished,
    Locked(String),
}

#[derive(Debug, Clone)]
pub struct ConsentInfo {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub agent: String,
    pub project: String,
    pub model_alias: String,
    pub provider_name: String,
    pub upstream_model: String,
    pub mode: ConsentMode,
    pub requested_at: String,
}

struct Pending {
    info: ConsentInfo,
    tx: oneshot::Sender<ConsentDecision>,
}

/// Everything the gateway needs for one request after authorization.
pub struct Plan {
    pub client: ClientConfig,
    pub model: ModelAlias,
    pub provider: ProviderConfig,
    pub price: Option<PriceVersion>,
    pub consent: String,
    pub upstream: Upstream,
}

struct GatewayHandle {
    url: String,
    shutdown: oneshot::Sender<()>,
}

type Notifier = Arc<dyn Fn(UiEvent) + Send + Sync>;

pub struct Core {
    /// Installation-wide locations (profiles.json lives in base.config_dir).
    pub base: Paths,
    paths_cell: RwLock<Paths>,
    pub settings: Mutex<AppSettings>,
    vault: RwLock<Option<Vault>>,
    audit_cell: RwLock<Arc<Audit>>,
    pub profiles: Mutex<ProfileStore>,
    user: RwLock<Option<Profile>>,
    pending: Mutex<HashMap<String, Pending>>,
    session_grants: Mutex<HashSet<(String, String)>>,
    rate: Mutex<RateLimiter>,
    redactor: RwLock<Redactor>,
    last_activity: Mutex<Instant>,
    pub http: reqwest::Client,
    notifier: RwLock<Option<Notifier>>,
    gateway: Mutex<Option<GatewayHandle>>,
    pub gateway_error: Mutex<Option<String>>,
    pub rt: tokio::runtime::Handle,
    pub kdf: KdfStrength,
    pub auto_start_gateway: bool,
}

impl Core {
    pub fn new(paths: Paths, rt: tokio::runtime::Handle) -> Result<Arc<Self>> {
        let audit = Arc::new(Audit::open(&paths.audit_db())?);
        let settings = AppSettings::load(&paths);
        Ok(Arc::new(Core {
            profiles: Mutex::new(ProfileStore::load(&paths.config_dir)),
            user: RwLock::new(None),
            base: paths.clone(),
            paths_cell: RwLock::new(paths),
            settings: Mutex::new(settings),
            vault: RwLock::new(None),
            audit_cell: RwLock::new(audit),
            pending: Mutex::new(HashMap::new()),
            session_grants: Mutex::new(HashSet::new()),
            rate: Mutex::new(RateLimiter::default()),
            redactor: RwLock::new(Redactor::default()),
            last_activity: Mutex::new(Instant::now()),
            http: providers::http_client(),
            notifier: RwLock::new(None),
            gateway: Mutex::new(None),
            gateway_error: Mutex::new(None),
            rt,
            kdf: KdfStrength::Standard,
            auto_start_gateway: true,
        }))
    }

    /// Test constructor: in-memory audit, fast KDF.
    pub fn new_for_tests(dir: &Path, rt: tokio::runtime::Handle) -> Arc<Self> {
        Arc::new(Core {
            profiles: Mutex::new(ProfileStore::load(dir)),
            user: RwLock::new(None),
            base: Paths::for_dir(dir),
            paths_cell: RwLock::new(Paths::for_dir(dir)),
            settings: Mutex::new(AppSettings::default()),
            vault: RwLock::new(None),
            audit_cell: RwLock::new(Arc::new(Audit::in_memory().unwrap())),
            pending: Mutex::new(HashMap::new()),
            session_grants: Mutex::new(HashSet::new()),
            rate: Mutex::new(RateLimiter::default()),
            redactor: RwLock::new(Redactor::default()),
            last_activity: Mutex::new(Instant::now()),
            http: providers::http_client(),
            notifier: RwLock::new(None),
            gateway: Mutex::new(None),
            gateway_error: Mutex::new(None),
            rt,
            kdf: KdfStrength::Fast,
            auto_start_gateway: false,
        })
    }

    /// Locations of the signed-in profile (or the base locations before sign-in / headless).
    pub fn paths(&self) -> Paths {
        self.paths_cell.read().unwrap().clone()
    }

    pub fn audit(&self) -> Arc<Audit> {
        self.audit_cell.read().unwrap().clone()
    }

    pub fn current_user(&self) -> Option<Profile> {
        self.user.read().unwrap().clone()
    }

    /// Switch the core to a profile: its own data folder, audit database and settings.
    fn activate_profile(&self, p: Profile) -> Result<()> {
        let dir = ProfileStore::profile_dir(&self.base.data_dir, &p);
        std::fs::create_dir_all(&dir)?;
        let paths = Paths::for_dir(&dir);
        let audit = Arc::new(Audit::open(&paths.audit_db())?);
        *self.settings.lock().unwrap() = AppSettings::load(&paths);
        *self.paths_cell.write().unwrap() = paths;
        *self.audit_cell.write().unwrap() = audit;
        self.audit().event("login", &format!("signed in as {}", p.username));
        *self.user.write().unwrap() = Some(p);
        Ok(())
    }

    pub fn register(&self, username: &str, display_name: &str, password: &str) -> Result<Profile> {
        let p = self.profiles.lock().unwrap().create(username, display_name, password)?;
        let p = self.profiles.lock().unwrap().login(&p.username, password)?;
        self.activate_profile(p.clone())?;
        Ok(p)
    }

    pub fn login(&self, username: &str, password: &str) -> Result<Profile> {
        let r = self.profiles.lock().unwrap().login(username, password);
        match r {
            Ok(p) => {
                self.activate_profile(p.clone())?;
                Ok(p)
            }
            Err(e) => {
                self.audit().event("login_failed", &format!("failed sign-in for '{}'", username.chars().take(40).collect::<String>()));
                Err(e)
            }
        }
    }

    /// Delete a profile and its data folder (vaults stored inside it, audit log, settings).
    /// Vault files saved elsewhere are not touched.
    pub fn delete_profile(&self, username: &str) -> Result<()> {
        if self.current_user().map(|u| u.username.eq_ignore_ascii_case(username)).unwrap_or(false) {
            self.logout();
        }
        let p = self.profiles.lock().unwrap().delete(username)?;
        let dir = ProfileStore::profile_dir(&self.base.data_dir, &p);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Sign out: lock the vault, stop the gateway and forget the profile.
    pub fn logout(&self) {
        self.lock("signed out");
        self.stop_gateway();
        if let Some(u) = self.user.write().unwrap().take() {
            self.audit().event("logout", &format!("{} signed out", u.username));
        }
        *self.paths_cell.write().unwrap() = self.base.clone();
    }

    pub fn set_notifier(&self, f: impl Fn(UiEvent) + Send + Sync + 'static) {
        *self.notifier.write().unwrap() = Some(Arc::new(f));
    }

    fn notify(&self, e: UiEvent) {
        let n = self.notifier.read().unwrap().clone();
        if let Some(n) = n {
            n(e);
        }
    }

    // ------------------------------------------------------------ vault state

    pub fn create_vault(self: &Arc<Self>, path: &Path, password: &str, keyfile: Option<&Path>) -> Result<()> {
        let v = Vault::create(path, password, keyfile, self.kdf)?;
        self.audit().event("vault", &format!("vault created at {}", path.display()));
        self.install_vault(v);
        Ok(())
    }

    pub fn unlock(self: &Arc<Self>, path: &Path, password: &str, keyfile: Option<&Path>) -> Result<()> {
        let v = Vault::open(path, password, keyfile).inspect_err(|_| self.audit().event("unlock_failed", &path.display().to_string()))?;
        self.audit().event("unlock", &format!("vault unlocked: {}", path.display()));
        self.install_vault(v);
        Ok(())
    }

    fn install_vault(self: &Arc<Self>, v: Vault) {
        {
            let mut s = self.settings.lock().unwrap();
            s.remember_vault(v.path());
            s.save(&self.paths());
        }
        *self.redactor.write().unwrap() = Redactor::new(v.provider_secrets());
        *self.vault.write().unwrap() = Some(v);
        self.touch();
        if self.auto_start_gateway && self.gateway.lock().unwrap().is_none() {
            if let Err(e) = self.start_gateway() {
                *self.gateway_error.lock().unwrap() = Some(e.to_string());
            }
        }
    }

    /// Lock: drop decrypted data (zeroized on drop), forget session grants, deny pending consents.
    pub fn lock(&self, reason: &str) {
        let was = self.vault.write().unwrap().take().is_some();
        self.session_grants.lock().unwrap().clear();
        let pending: Vec<Pending> = self.pending.lock().unwrap().drain().map(|(_, p)| p).collect();
        for p in pending {
            let _ = p.tx.send(ConsentDecision::Deny);
        }
        *self.redactor.write().unwrap() = Redactor::default();
        if was {
            self.audit().event("lock", reason);
            self.notify(UiEvent::Locked(reason.to_string()));
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.read().unwrap().is_some()
    }

    pub fn with_vault<R>(&self, f: impl FnOnce(&Vault) -> R) -> Option<R> {
        self.vault.read().unwrap().as_ref().map(f)
    }

    /// Mutate the vault (the closure is expected to call `save`). Refreshes the redactor.
    pub fn with_vault_mut<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R>) -> Result<R> {
        let mut g = self.vault.write().unwrap();
        let v = g.as_mut().ok_or_else(|| anyhow!("the vault is locked"))?;
        let r = f(v)?;
        *self.redactor.write().unwrap() = Redactor::new(v.provider_secrets());
        Ok(r)
    }

    pub fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    /// Periodic housekeeping (called by the UI timer): auto-lock after inactivity.
    pub fn tick(&self) {
        let minutes = self.with_vault(|v| v.config.security.auto_lock_minutes).unwrap_or(0);
        if minutes > 0 && self.last_activity.lock().unwrap().elapsed() > Duration::from_secs(minutes as u64 * 60) {
            self.lock("auto-lock after inactivity");
        }
    }

    pub fn redact(&self, s: &str) -> String {
        self.redactor.read().unwrap().redact(s)
    }

    // ---------------------------------------------------------------- gateway

    pub fn start_gateway(self: &Arc<Self>) -> Result<String> {
        let (host, port) = self.with_vault(|v| (v.config.gateway.host.clone(), v.config.gateway.port)).unwrap_or(("127.0.0.1".into(), 8765));
        let addr = format!("{host}:{port}");
        let listener = std::net::TcpListener::bind(&addr).map_err(|e| anyhow!("cannot listen on {addr}: {e}"))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr);
        let (tx, rx) = oneshot::channel::<()>();
        let app = crate::gateway::router(self.clone());
        self.rt.spawn(async move {
            match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => {
                    let _ = axum::serve(l, app)
                        .with_graceful_shutdown(async move {
                            let _ = rx.await;
                        })
                        .await;
                }
                Err(e) => eprintln!("gateway listener error: {e}"),
            }
        });
        let url = format!("http://{addr}/v1");
        *self.gateway.lock().unwrap() = Some(GatewayHandle { url: url.clone(), shutdown: tx });
        *self.gateway_error.lock().unwrap() = None;
        self.audit().event("gateway", &format!("gateway listening on {url}"));
        Ok(url)
    }

    pub fn stop_gateway(&self) {
        if let Some(h) = self.gateway.lock().unwrap().take() {
            let _ = h.shutdown.send(());
        }
    }

    pub fn restart_gateway(self: &Arc<Self>) -> Result<String> {
        self.stop_gateway();
        std::thread::sleep(Duration::from_millis(150));
        self.start_gateway()
    }

    pub fn gateway_url(&self) -> Option<String> {
        self.gateway.lock().unwrap().as_ref().map(|g| g.url.clone())
    }

    // ----------------------------------------------------------------- policy

    /// Authorize a client request. Performs every check *before* any secret is touched,
    /// asks the user for consent when needed, then resolves the provider key in-process.
    pub async fn authorize(self: &Arc<Self>, token: Option<&str>, alias: &str, agent: &str, project: &str) -> Result<Plan, (Denial, Option<ClientConfig>)> {
        let token = token.map(str::trim).filter(|t| !t.is_empty()).ok_or((Denial::MissingToken, None))?;
        let hash = hash_token(token);

        // Phase 1 - checks under a short read lock.
        let (client, model, provider, price, need_ask) = {
            let g = self.vault.read().unwrap();
            let v = g.as_ref().ok_or((Denial::Locked, None))?;
            let cfg = &v.config;
            let client = cfg.client_by_hash(&hash).cloned().ok_or((Denial::InvalidToken, None))?;
            let c = Some(client.clone());
            if client.revoked {
                return Err((Denial::Revoked, c));
            }
            if let Some(exp) = &client.expires_at {
                if chrono::DateTime::parse_from_rfc3339(exp).map(|e| e < chrono::Utc::now()).unwrap_or(true) {
                    return Err((Denial::Expired, c));
                }
            }
            let model = cfg.model(alias).filter(|m| m.enabled).cloned().ok_or((Denial::UnknownModel(alias.to_string()), c.clone()))?;
            if !client.allowed_models.is_empty() && !client.allowed_models.iter().any(|m| m == alias || m == "*") {
                return Err((Denial::ModelNotAllowed(alias.to_string()), c));
            }
            let provider = cfg
                .provider(&model.provider_id)
                .filter(|p| p.enabled)
                .cloned()
                .ok_or((Denial::ProviderUnavailable("provider disabled or missing".into()), c.clone()))?;
            providers::check_egress(&provider).map_err(|e| (Denial::ProviderUnavailable(e.to_string()), c.clone()))?;
            if !self.rate.lock().unwrap().check(&client.id, client.rpm_limit) {
                return Err((Denial::RateLimited(client.rpm_limit), c));
            }
            // Budgets (evaluated in USD).
            let to_usd = |m: HashMap<String, f64>| m.into_iter().map(|(cur, amt)| amt / cfg.fx_per_usd(&cur)).sum::<f64>();
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            if client.daily_budget > 0.0 {
                let spent = to_usd(self.audit().client_spend(&client.id, &today));
                if spent >= client.daily_budget {
                    return Err((Denial::BudgetExceeded(format!("daily budget {:.2} USD reached", client.daily_budget)), c));
                }
            }
            if client.monthly_budget > 0.0 {
                let month = format!("{}-01", &today[..7]);
                let spent = to_usd(self.audit().client_spend(&client.id, &month));
                if spent >= client.monthly_budget {
                    return Err((Denial::BudgetExceeded(format!("monthly budget {:.2} USD reached", client.monthly_budget)), c));
                }
            }
            let price = pricing::price_for(&cfg.prices, alias, &today).cloned();
            let now = chrono::Utc::now();
            let rule = cfg.consent_rules.iter().any(|r| {
                r.client_id == client.id
                    && (r.model_alias == alias || r.model_alias == "*")
                    && r.expires_at.as_deref().and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok()).map(|e| e > now).unwrap_or(true)
            });
            let session = self.session_grants.lock().unwrap().contains(&(client.id.clone(), alias.to_string()));
            let consent = if client.consent_mode == ConsentMode::Auto {
                Some("auto")
            } else if rule {
                Some("rule")
            } else if session {
                Some("session")
            } else {
                None
            };
            (client, model, provider, price, consent)
        };

        // Phase 2 - interactive consent (no locks held while waiting).
        let consent = match need_ask {
            Some(c) => c.to_string(),
            None => {
                let info = ConsentInfo {
                    id: new_id(),
                    client_id: client.id.clone(),
                    client_name: client.name.clone(),
                    agent: agent.to_string(),
                    project: if project.is_empty() { client.project.clone() } else { project.to_string() },
                    model_alias: alias.to_string(),
                    provider_name: provider.name.clone(),
                    upstream_model: model.upstream_model.clone(),
                    mode: client.consent_mode,
                    requested_at: now_rfc3339(),
                };
                let decision = match self.request_consent(info).await {
                    Some(d) => d,
                    None => return Err((Denial::ConsentTimeout, Some(client))),
                };
                match decision {
                    ConsentDecision::Once => "once".into(),
                    ConsentDecision::Session => {
                        self.session_grants.lock().unwrap().insert((client.id.clone(), alias.to_string()));
                        "session".into()
                    }
                    ConsentDecision::Always => {
                        let rule = ConsentRule { id: new_id(), client_id: client.id.clone(), model_alias: alias.to_string(), created_at: now_rfc3339(), expires_at: None };
                        let cl = client.clone();
                        let r = tokio::task::block_in_place(|| {
                            self.with_vault_mut(|v| {
                                v.config.consent_rules.push(rule);
                                v.save()
                            })
                        });
                        if r.is_err() {
                            return Err((Denial::Locked, Some(cl)));
                        }
                        "rule".into()
                    }
                    ConsentDecision::Deny => return Err((Denial::ConsentDenied, Some(client))),
                }
            }
        };

        // Phase 3 - resolve the secret (vault may have been locked while waiting).
        let secret = {
            let g = self.vault.read().unwrap();
            let v = g.as_ref().ok_or((Denial::Locked, Some(client.clone())))?;
            match provider.secret_entry.as_deref() {
                Some(id) => Some(v.provider_secret(id).ok_or((Denial::ProviderUnavailable("API key missing in vault".into()), Some(client.clone())))?),
                None => None,
            }
        };
        let upstream = Upstream::from_config(&provider, secret);
        Ok(Plan { client, model, provider, price, consent, upstream })
    }

    /// Returns None when the user did not answer in time.
    async fn request_consent(&self, info: ConsentInfo) -> Option<ConsentDecision> {
        let timeout = self.with_vault(|v| v.config.gateway.consent_timeout_s).unwrap_or(90);
        let (tx, rx) = oneshot::channel();
        let id = info.id.clone();
        self.pending.lock().unwrap().insert(id.clone(), Pending { info: info.clone(), tx });
        self.notify(UiEvent::ConsentRequested(info));
        let r = tokio::time::timeout(Duration::from_secs(timeout), rx).await;
        self.pending.lock().unwrap().remove(&id);
        self.notify(UiEvent::ConsentClosed(id));
        match r {
            Ok(Ok(d)) => Some(d),
            Ok(Err(_)) => Some(ConsentDecision::Deny),
            Err(_) => {
                self.audit().event("consent_timeout", "consent request timed out");
                None
            }
        }
    }

    pub fn pending_consents(&self) -> Vec<ConsentInfo> {
        let mut v: Vec<ConsentInfo> = self.pending.lock().unwrap().values().map(|p| p.info.clone()).collect();
        v.sort_by(|a, b| a.requested_at.cmp(&b.requested_at));
        v
    }

    pub fn resolve_consent(&self, id: &str, decision: ConsentDecision) {
        self.touch();
        if let Some(p) = self.pending.lock().unwrap().remove(id) {
            self.audit().event("consent", &format!("{:?} for {} / {}", decision, p.info.client_name, p.info.model_alias));
            let _ = p.tx.send(decision);
        }
    }

    pub fn session_grants(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self.session_grants.lock().unwrap().iter().cloned().collect();
        v.sort();
        v
    }

    pub fn revoke_session_grant(&self, client_id: &str, alias: &str) {
        self.session_grants.lock().unwrap().remove(&(client_id.to_string(), alias.to_string()));
    }

    pub fn revoke_all_sessions_for(&self, client_id: &str) {
        self.session_grants.lock().unwrap().retain(|(c, _)| c != client_id);
    }

    pub fn finish(&self, mut rec: RequestRecord) {
        rec.error = self.redact(&rec.error);
        rec.decision_reason = self.redact(&rec.decision_reason);
        if let Err(e) = self.audit().record(&rec) {
            eprintln!("audit write failed: {e}");
        }
        self.notify(UiEvent::RequestFinished);
    }

    /// Display-currency conversion factor for a given currency.
    pub fn fx_to_display(&self) -> impl Fn(&str) -> f64 + use<> {
        let (rates, display) = self
            .with_vault(|v| (v.config.fx_rates.clone(), v.config.display_currency.clone()))
            .unwrap_or_else(|| (vec![], "USD".into()));
        move |cur: &str| {
            let per = |c: &str| rates.iter().find(|r| r.currency.eq_ignore_ascii_case(c)).map(|r| r.per_usd).filter(|r| *r > 0.0).unwrap_or(1.0);
            per(&display) / per(cur)
        }
    }
}
