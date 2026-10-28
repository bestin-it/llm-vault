//! Policy primitives: client tokens, denials, rate limiting, consent decisions.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use base64::Engine;
use sha2::{Digest, Sha256};

pub const TOKEN_PREFIX: &str = "lvk_";

/// Create a new client token. Returns (plaintext token, sha256 hex, display prefix).
/// The plaintext is shown to the user exactly once and never stored.
pub fn new_client_token() -> (String, String, String) {
    let mut raw = [0u8; 32];
    rand::fill(&mut raw);
    let token = format!("{TOKEN_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw));
    let hash = hash_token(&token);
    let prefix = token.chars().take(10).collect::<String>();
    (token, hash, prefix)
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Denial {
    Locked,
    MissingToken,
    InvalidToken,
    Revoked,
    Expired,
    UnknownModel(String),
    ModelNotAllowed(String),
    ProviderUnavailable(String),
    RateLimited(u32),
    BudgetExceeded(String),
    ConsentDenied,
    ConsentTimeout,
    UnsupportedEndpoint(String),
}

impl Denial {
    pub fn status(&self) -> u16 {
        match self {
            Denial::Locked => 423,
            Denial::MissingToken | Denial::InvalidToken | Denial::Revoked | Denial::Expired => 401,
            Denial::UnknownModel(_) => 404,
            Denial::ModelNotAllowed(_) | Denial::ConsentDenied | Denial::ConsentTimeout => 403,
            Denial::ProviderUnavailable(_) => 502,
            Denial::RateLimited(_) | Denial::BudgetExceeded(_) => 429,
            Denial::UnsupportedEndpoint(_) => 400,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Denial::Locked => "vault_locked",
            Denial::MissingToken => "missing_token",
            Denial::InvalidToken => "invalid_token",
            Denial::Revoked => "token_revoked",
            Denial::Expired => "token_expired",
            Denial::UnknownModel(_) => "model_not_found",
            Denial::ModelNotAllowed(_) => "model_not_allowed",
            Denial::ProviderUnavailable(_) => "provider_unavailable",
            Denial::RateLimited(_) => "rate_limited",
            Denial::BudgetExceeded(_) => "budget_exceeded",
            Denial::ConsentDenied => "consent_denied",
            Denial::ConsentTimeout => "consent_timeout",
            Denial::UnsupportedEndpoint(_) => "unsupported_endpoint",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Denial::Locked => "LLM Vault is locked. Ask the vault owner to unlock it.".into(),
            Denial::MissingToken => "Missing client token (Authorization: Bearer lvk_...).".into(),
            Denial::InvalidToken => "Invalid client token.".into(),
            Denial::Revoked => "This client token has been revoked.".into(),
            Denial::Expired => "This client token has expired.".into(),
            Denial::UnknownModel(m) => format!("Model '{m}' is not configured in LLM Vault."),
            Denial::ModelNotAllowed(m) => format!("This client is not allowed to use model '{m}'."),
            Denial::ProviderUnavailable(m) => format!("Provider unavailable: {m}"),
            Denial::RateLimited(n) => format!("Rate limit exceeded ({n} requests/minute)."),
            Denial::BudgetExceeded(m) => format!("Budget exceeded: {m}"),
            Denial::ConsentDenied => "The vault owner denied this request.".into(),
            Denial::ConsentTimeout => "No consent was given in time; request denied.".into(),
            Denial::UnsupportedEndpoint(m) => m.clone(),
        }
    }
}

/// What the user chose in the consent dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Deny,
    Once,
    Session,
    Always,
}

/// Sliding-window requests-per-minute limiter.
#[derive(Default)]
pub struct RateLimiter {
    windows: HashMap<String, VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn check(&mut self, key: &str, rpm: u32) -> bool {
        if rpm == 0 {
            return true;
        }
        let now = Instant::now();
        let w = self.windows.entry(key.to_string()).or_default();
        while let Some(t) = w.front() {
            if now.duration_since(*t) > Duration::from_secs(60) {
                w.pop_front();
            } else {
                break;
            }
        }
        if w.len() as u32 >= rpm {
            return false;
        }
        w.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let (t, h, p) = new_client_token();
        assert!(t.starts_with(TOKEN_PREFIX));
        assert_eq!(hash_token(&t), h);
        assert!(t.starts_with(&p));
        assert!(t.len() > 40);
    }

    #[test]
    fn rate_limiter() {
        let mut r = RateLimiter::default();
        assert!(r.check("a", 2));
        assert!(r.check("a", 2));
        assert!(!r.check("a", 2));
        assert!(r.check("b", 2));
        assert!(r.check("a", 0));
    }
}
