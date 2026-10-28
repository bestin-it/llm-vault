//! Token usage normalization and cost calculation with versioned price lists.
//!
//! cost = input_uncached * P_in / 1M + output * P_out / 1M + cache_read * P_cache_read / 1M
//!      + cache_write * P_cache_write / 1M (+ reasoning priced separately when configured)

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::PriceVersion;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// Usage numbers returned by the provider.
    Reported,
    /// Estimated by the gateway (no usage returned).
    Estimated,
    /// Not available (e.g. failed request).
    #[default]
    Unavailable,
}

impl UsageSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            UsageSource::Reported => "reported",
            UsageSource::Estimated => "estimated",
            UsageSource::Unavailable => "unavailable",
        }
    }
}

/// Normalized usage. `input` counts *all* prompt tokens including cached ones;
/// `reasoning` is a subset of `output`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub reasoning: u64,
    pub source: UsageSource,
}

impl Usage {
    /// Parse an OpenAI-style `usage` object.
    pub fn from_openai(u: &Value) -> Option<Usage> {
        if !u.is_object() {
            return None;
        }
        let input = u["prompt_tokens"].as_u64().or(u["input_tokens"].as_u64()).unwrap_or(0);
        let output = u["completion_tokens"].as_u64().or(u["output_tokens"].as_u64()).unwrap_or(0);
        if input == 0 && output == 0 && u["total_tokens"].as_u64().unwrap_or(0) == 0 {
            return None;
        }
        Some(Usage {
            input,
            output,
            cache_read: u["prompt_tokens_details"]["cached_tokens"].as_u64().unwrap_or(0),
            cache_write: 0,
            reasoning: u["completion_tokens_details"]["reasoning_tokens"].as_u64().unwrap_or(0),
            source: UsageSource::Reported,
        })
    }

    /// Rough estimate (~4 characters per token) when the provider does not report usage.
    pub fn estimate(prompt_chars: usize, completion_chars: usize) -> Usage {
        Usage {
            input: (prompt_chars as u64).div_ceil(4),
            output: (completion_chars as u64).div_ceil(4),
            source: UsageSource::Estimated,
            ..Default::default()
        }
    }

    pub fn total(&self) -> u64 {
        self.input + self.output
    }
}

/// Pick the price version valid at `date` (YYYY-MM-DD) for `alias`.
pub fn price_for<'a>(prices: &'a [PriceVersion], alias: &str, date: &str) -> Option<&'a PriceVersion> {
    prices
        .iter()
        .filter(|p| p.alias == alias && p.effective_from.as_str() <= date)
        .max_by(|a, b| a.effective_from.cmp(&b.effective_from))
}

/// Cost in the price's currency.
pub fn cost(u: &Usage, p: &PriceVersion) -> f64 {
    let m = 1_000_000.0;
    let uncached = u.input.saturating_sub(u.cache_read + u.cache_write) as f64;
    let (out_regular, reasoning) = if p.reasoning > 0.0 { (u.output.saturating_sub(u.reasoning), u.reasoning) } else { (u.output, 0) };
    uncached * p.input / m
        + out_regular as f64 * p.output / m
        + reasoning as f64 * p.reasoning / m
        + u.cache_read as f64 * p.cache_read / m
        + u.cache_write as f64 * p.cache_write / m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price() -> PriceVersion {
        PriceVersion {
            id: "p".into(),
            alias: "foundry-glm".into(),
            currency: "USD".into(),
            input: 2.0,
            output: 8.0,
            cache_read: 0.5,
            cache_write: 0.0,
            reasoning: 0.0,
            effective_from: "2026-01-01".into(),
            source: "test".into(),
            estimated: false,
        }
    }

    #[test]
    fn cost_formula_matches_spec() {
        // 1M uncached input + 1M output + 1M cached input = 2 + 8 + 0.5
        let u = Usage { input: 2_000_000, output: 1_000_000, cache_read: 1_000_000, ..Default::default() };
        assert!((cost(&u, &price()) - 10.5).abs() < 1e-9);
    }

    #[test]
    fn picks_price_version_by_date() {
        let mut p2 = price();
        p2.id = "p2".into();
        p2.input = 1.0;
        p2.effective_from = "2026-06-01".into();
        let list = vec![price(), p2];
        assert_eq!(price_for(&list, "foundry-glm", "2026-03-01").unwrap().id, "p");
        assert_eq!(price_for(&list, "foundry-glm", "2026-07-01").unwrap().id, "p2");
        assert!(price_for(&list, "foundry-glm", "2025-12-31").is_none());
    }

    #[test]
    fn parses_openai_usage() {
        let u = Usage::from_openai(&serde_json::json!({"prompt_tokens": 100, "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 40}, "completion_tokens_details": {"reasoning_tokens": 5}}))
        .unwrap();
        assert_eq!((u.input, u.output, u.cache_read, u.reasoning), (100, 20, 40, 5));
        assert!(Usage::from_openai(&Value::Null).is_none());
    }
}
