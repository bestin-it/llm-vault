//! Log / error redaction. Every string that leaves the gateway towards a client or is written
//! to the audit log passes through `Redactor::redact`.

use std::sync::LazyLock;

use regex::Regex;
use zeroize::Zeroizing;

pub const MASK: &str = "[REDACTED]";

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"sk-ant-[A-Za-z0-9_\-]{8,}",
        r"sk-(proj-|svcacct-|or-v1-)?[A-Za-z0-9_\-*]{8,}",
        r"AIza[0-9A-Za-z_\-]{20,}",
        r"gsk_[A-Za-z0-9]{10,}",
        r"xai-[A-Za-z0-9]{10,}",
        r"hf_[A-Za-z0-9]{10,}",
        r"lvk_[A-Za-z0-9_\-]{10,}",
        r"(?i)bearer\s+[A-Za-z0-9._\-~+/=]{8,}",
        r#"(?i)(api[-_]?key|x-api-key|authorization)("?\s*[:=]\s*"?)[A-Za-z0-9._\-~+/=*]{8,}"#,
    ]
    .iter()
    .map(|p| Regex::new(p).expect("valid redaction regex"))
    .collect()
});

#[derive(Default)]
pub struct Redactor {
    secrets: Vec<Zeroizing<String>>,
}

impl Redactor {
    pub fn new(secrets: Vec<Zeroizing<String>>) -> Self {
        // Very short "secrets" would mangle normal text; real keys are long.
        Redactor { secrets: secrets.into_iter().filter(|s| s.len() >= 6).collect() }
    }

    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();
        for s in &self.secrets {
            if out.contains(s.as_str()) {
                out = out.replace(s.as_str(), MASK);
            }
            // Also catch partially-echoed keys (providers often print the first/last chars).
            if s.len() >= 16 {
                if let (Some(head), Some(tail)) = (s.get(..10), s.get(s.len() - 6..)) {
                    out = out.replace(head, MASK).replace(tail, MASK);
                }
            }
        }
        for re in PATTERNS.iter() {
            out = re
                .replace_all(&out, |c: &regex::Captures| if c.len() >= 3 { format!("{}{}{}", &c[1], &c[2], MASK) } else { MASK.to_string() })
                .into_owned();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_secret_and_partial_echo() {
        let key = "zz-super-secret-provider-key-1234567890";
        let r = Redactor::new(vec![Zeroizing::new(key.to_string())]);
        let msg = format!("Incorrect API key provided: {}****{}", &key[..10], &key[key.len() - 6..]);
        let out = r.redact(&msg);
        assert!(!out.contains(&key[..10]), "{out}");
        assert!(!out.contains(&key[key.len() - 6..]), "{out}");
        assert!(!r.redact(&format!("x {key} y")).contains(key));
    }

    #[test]
    fn redacts_common_key_patterns() {
        let r = Redactor::default();
        for s in [
            "sk-proj-abcdefghijklmnop1234",
            "sk-ant-api03-abcdefghijkl",
            "AIzaSyA1234567890abcdefghijk",
            "Authorization: Bearer abc.def.ghi12345",
            "{\"api_key\": \"0123456789abcdef\"}",
            "hf_abcdefghijklmnop",
        ] {
            let out = r.redact(s);
            assert!(out.contains(MASK), "not redacted: {s} -> {out}");
        }
        assert_eq!(r.redact("hello world"), "hello world");
    }
}
