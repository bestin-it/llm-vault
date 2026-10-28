//! Gateway configuration (providers, model aliases, clients, consent rules, prices).
//!
//! The configuration is stored *inside* the encrypted KDBX file (database meta custom data),
//! so it is covered by the same encryption and HMAC integrity protection as the secrets.
//! An agent that can write files in the user profile therefore cannot silently redirect a
//! provider's base URL to an attacker-controlled host to harvest the API key.

use serde::{Deserialize, Serialize};

pub const CONFIG_CUSTOM_DATA_KEY: &str = "llmvault.config.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct VaultConfig {
    pub gateway: GatewaySettings,
    pub security: SecuritySettings,
    pub display_currency: String,
    pub fx_rates: Vec<FxRate>,
    pub providers: Vec<ProviderConfig>,
    pub models: Vec<ModelAlias>,
    pub prices: Vec<PriceVersion>,
    pub clients: Vec<ClientConfig>,
    pub consent_rules: Vec<ConsentRule>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            gateway: GatewaySettings::default(),
            security: SecuritySettings::default(),
            display_currency: "USD".into(),
            fx_rates: vec![
                FxRate { currency: "USD".into(), per_usd: 1.0, date: "2026-10-01".into(), source: "base".into() },
                FxRate { currency: "EUR".into(), per_usd: 0.92, date: "2026-10-01".into(), source: "manual - update in Settings".into() },
                FxRate { currency: "PLN".into(), per_usd: 3.95, date: "2026-10-01".into(), source: "manual - update in Settings".into() },
            ],
            providers: Vec::new(),
            models: Vec::new(),
            prices: Vec::new(),
            clients: Vec::new(),
            consent_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GatewaySettings {
    pub host: String,
    pub port: u16,
    /// Seconds a request waits for the user's consent before it is denied.
    pub consent_timeout_s: u64,
    /// Store prompt/response bodies in the audit log. Off by default (privacy).
    pub log_bodies: bool,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self { host: "127.0.0.1".into(), port: 8765, consent_timeout_s: 90, log_bodies: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SecuritySettings {
    /// Lock the vault after this many minutes without user interaction (0 = never).
    pub auto_lock_minutes: u32,
    /// Clear copied passwords from the clipboard after N seconds.
    pub clipboard_clear_s: u32,
    /// Delay before consent buttons become clickable (anti-clickjacking / UI automation).
    pub consent_arm_ms: u32,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self { auto_lock_minutes: 15, clipboard_clear_s: 15, consent_arm_ms: 1200 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FxRate {
    pub currency: String,
    /// Units of `currency` for 1 USD.
    pub per_usd: f64,
    pub date: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Any OpenAI-compatible Chat Completions API (OpenAI, Groq, Mistral, OpenRouter, ...).
    OpenAi,
    /// Azure OpenAI classic deployments: /openai/deployments/{model}/chat/completions?api-version=
    AzureOpenAi,
    /// Anthropic Messages API.
    Anthropic,
    /// Ollama (local daemon or ollama.com cloud). OpenAI-compatible /v1 + native /api/tags.
    Ollama,
}

impl ProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderKind::OpenAi => "openai",
            ProviderKind::AzureOpenAi => "azure_openai",
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Ollama => "ollama",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthStyle {
    Bearer,
    ApiKeyHeader,
    XApiKey,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderConfig {
    pub id: String,
    pub name: String,
    /// Catalog preset id (e.g. "ollama-cloud"), informational.
    pub preset: String,
    pub kind: ProviderKind,
    pub base_url: String,
    pub auth: AuthStyle,
    /// UUID of the KDBX entry that holds the API key in its Password field.
    pub secret_entry: Option<String>,
    #[serde(default)]
    pub api_version: Option<String>,
    /// Plain HTTP is only allowed for loopback hosts unless explicitly enabled.
    #[serde(default)]
    pub allow_http: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: String,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelAlias {
    /// Name clients use, e.g. "foundry-glm".
    pub alias: String,
    pub provider_id: String,
    /// Model / deployment name at the provider.
    pub upstream_model: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PriceVersion {
    pub id: String,
    pub alias: String,
    pub currency: String,
    /// Prices per 1M tokens.
    pub input: f64,
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
    #[serde(default)]
    pub cache_write: f64,
    /// 0 = reasoning tokens billed as output.
    #[serde(default)]
    pub reasoning: f64,
    /// ISO date (YYYY-MM-DD) from which this price applies.
    pub effective_from: String,
    #[serde(default)]
    pub source: String,
    /// True for estimated infrastructure cost (local models), not an invoice price.
    #[serde(default)]
    pub estimated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// Ask the user for every request (unless a rule matches).
    Ask,
    /// Ask once per client+model, then allow until the vault is locked.
    Session,
    /// Pre-approved: no prompt (limits still apply).
    Auto,
}

impl ConsentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConsentMode::Ask => "ask",
            ConsentMode::Session => "session",
            ConsentMode::Auto => "auto",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "session" => ConsentMode::Session,
            "auto" => ConsentMode::Auto,
            _ => ConsentMode::Ask,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub project: String,
    /// SHA-256 (hex) of the client token. The token itself is never stored.
    pub token_hash: String,
    /// First characters of the token, for recognition in the UI.
    pub token_prefix: String,
    /// Allowed model aliases; empty = all enabled aliases.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    pub consent_mode: ConsentMode,
    /// RFC3339; None = no expiry.
    pub expires_at: Option<String>,
    #[serde(default)]
    pub daily_budget: f64,
    #[serde(default)]
    pub monthly_budget: f64,
    #[serde(default)]
    pub rpm_limit: u32,
    #[serde(default)]
    pub revoked: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsentRule {
    pub id: String,
    pub client_id: String,
    /// "*" = any model the client is allowed to use.
    pub model_alias: String,
    pub created_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl VaultConfig {
    pub fn provider(&self, id: &str) -> Option<&ProviderConfig> {
        self.providers.iter().find(|p| p.id == id)
    }
    pub fn model(&self, alias: &str) -> Option<&ModelAlias> {
        self.models.iter().find(|m| m.alias == alias)
    }
    pub fn client(&self, id: &str) -> Option<&ClientConfig> {
        self.clients.iter().find(|c| c.id == id)
    }
    pub fn client_by_hash(&self, hash: &str) -> Option<&ClientConfig> {
        use subtle::ConstantTimeEq;
        self.clients
            .iter()
            .find(|c| c.token_hash.as_bytes().ct_eq(hash.as_bytes()).into())
    }
    pub fn fx_per_usd(&self, currency: &str) -> f64 {
        self.fx_rates
            .iter()
            .find(|r| r.currency.eq_ignore_ascii_case(currency))
            .map(|r| r.per_usd)
            .filter(|r| *r > 0.0)
            .unwrap_or(1.0)
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
