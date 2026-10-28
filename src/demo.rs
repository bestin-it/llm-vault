//! `--demo` mode: an isolated, throw-away vault with clearly synthetic data, used for
//! screenshots, videos and trying the app without real keys. Never touches the user's data.

use std::sync::Arc;

use anyhow::Result;
use rand::RngExt;

use llmvault::audit::RequestRecord;
use llmvault::config::{AuthStyle, ClientConfig, ConsentMode, ConsentRule, ModelAlias, PriceVersion, ProviderConfig, ProviderKind, new_id, now_rfc3339};
use llmvault::core::Core;
use llmvault::policy::new_client_token;
use llmvault::pricing::{Usage, UsageSource};
use llmvault::vault::{EntryInput, generate_password};

pub const DEMO_PASSWORD: &str = "demo-vault-password-2026";

pub struct Demo {
    /// Token of the "API Analyst" client (consent mode: ask) - used to trigger a live consent prompt.
    pub ask_token: String,
}

fn price(alias: &str, input: f64, output: f64, cache: f64, estimated: bool, source: &str) -> PriceVersion {
    PriceVersion {
        id: new_id(),
        alias: alias.into(),
        currency: "USD".into(),
        input,
        output,
        cache_read: cache,
        cache_write: 0.0,
        reasoning: 0.0,
        effective_from: "2026-01-01".into(),
        source: source.into(),
        estimated,
    }
}

pub fn setup(core: &Arc<Core>) -> Result<Demo> {
    let path = core.paths().data_dir.join("DEMO - LLM Vault.kdbx");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("kdbx.bak"));
    core.create_vault(&path, DEMO_PASSWORD, None)?;
    let (ask_token, ask_hash, ask_prefix) = new_client_token();
    let mut client_ids = Vec::new();

    core.with_vault_mut(|v| {
        // ---- password manager entries
        let groups = v.groups();
        let gid = |name: &str| groups.iter().find(|g| g.name == name).map(|g| g.id.clone());
        for (g, title, user, url) in [
            ("Internet", "GitHub", "dev@contoso.example", "https://github.com"),
            ("Internet", "Atlassian Jira", "dev@contoso.example", "https://contoso.atlassian.net"),
            ("Internet", "AWS console (dev)", "iam-dev-user", "https://console.aws.amazon.com"),
            ("Email", "Microsoft 365", "dev@contoso.example", "https://outlook.office.com"),
            ("Servers & SSH", "Bastion host", "ops", "ssh://bastion.contoso.example"),
            ("Servers & SSH", "PostgreSQL staging", "app_rw", "postgres://db-stg.contoso.example:5432"),
            ("General", "Wi-Fi office", "CONTOSO-5G", ""),
            ("General", "Code signing certificate PIN", "", ""),
        ] {
            v.upsert_entry(EntryInput {
                group_id: gid(g),
                title: title.into(),
                username: user.into(),
                password: Some(zeroize::Zeroizing::new(generate_password(22, true, true, true))),
                url: url.into(),
                notes: "Synthetic demo entry.".into(),
                tags: "demo".into(),
                ..Default::default()
            })?;
        }

        // ---- providers (fake keys - the demo never calls them)
        let fake = |p: &str| format!("{p}-DEMO-NOT-A-REAL-KEY-{}", generate_password(24, true, true, false));
        let foundry_key = v.set_provider_secret(None, "Azure AI Foundry API key", "https://contoso-ai.services.ai.azure.com", &fake("foundry"))?;
        let cloud_key = v.set_provider_secret(None, "Ollama Cloud API key", "https://ollama.com", &fake("ollama"))?;
        let ant_key = v.set_provider_secret(None, "Anthropic API key", "https://api.anthropic.com", &fake("sk-ant"))?;
        let or_key = v.set_provider_secret(None, "OpenRouter API key", "https://openrouter.ai/api/v1", &fake("sk-or"))?;
        let mk = |id: &str, name: &str, preset: &str, kind: ProviderKind, url: &str, auth: AuthStyle, key: Option<String>| ProviderConfig {
            id: id.into(),
            name: name.into(),
            preset: preset.into(),
            kind,
            base_url: url.into(),
            auth,
            secret_entry: key,
            api_version: None,
            allow_http: false,
            enabled: true,
            created_at: now_rfc3339(),
        };
        v.config.providers = vec![
            mk("foundry", "Azure AI Foundry", "azure-foundry", ProviderKind::OpenAi, "https://contoso-ai.services.ai.azure.com/openai/v1", AuthStyle::ApiKeyHeader, Some(foundry_key)),
            mk("ollama-cloud", "Ollama Cloud", "ollama-cloud", ProviderKind::Ollama, "https://ollama.com", AuthStyle::Bearer, Some(cloud_key)),
            mk("ollama-local", "Ollama (local)", "ollama-local", ProviderKind::Ollama, "http://127.0.0.1:11434", AuthStyle::None, None),
            mk("anthropic", "Anthropic", "anthropic", ProviderKind::Anthropic, "https://api.anthropic.com", AuthStyle::XApiKey, Some(ant_key)),
            mk("openrouter", "OpenRouter", "openrouter", ProviderKind::OpenAi, "https://openrouter.ai/api/v1", AuthStyle::Bearer, Some(or_key)),
            mk("llama-cpp", "llama.cpp (local)", "llama-cpp", ProviderKind::OpenAi, "http://127.0.0.1:8080/v1", AuthStyle::None, None),
        ];
        let m = |alias: &str, p: &str, up: &str, d: &str| ModelAlias { alias: alias.into(), provider_id: p.into(), upstream_model: up.into(), description: d.into(), enabled: true };
        v.config.models = vec![
            m("foundry-glm", "foundry", "glm-4.6", "GLM via Azure AI Foundry"),
            m("foundry-gpt5-mini", "foundry", "gpt-5-mini", "GPT-5 mini via Foundry"),
            m("gpt-oss-120b-cloud", "ollama-cloud", "gpt-oss:120b", "gpt-oss 120B on ollama.com"),
            m("qwen-local", "ollama-local", "qwen3:8b", "Qwen3 8B on this workstation"),
            m("qwen3-0.6b", "ollama-local", "qwen3:0.6b", "Qwen3 0.6B on this workstation (live demo model)"),
            m("summarizer", "ollama-local", "qwen3:8b", "What scripts call - the engine behind it can change"),
            m("claude-sonnet", "anthropic", "claude-sonnet-5-5", "Claude Sonnet"),
            m("router-qwen-coder", "openrouter", "qwen/qwen3-coder", "Qwen3 Coder via OpenRouter"),
        ];
        v.config.prices = vec![
            price("foundry-glm", 2.0, 8.0, 0.5, false, "demo price list"),
            price("foundry-gpt5-mini", 0.25, 2.0, 0.025, false, "demo price list"),
            price("gpt-oss-120b-cloud", 0.6, 2.4, 0.0, false, "demo price list"),
            price("qwen-local", 0.15, 0.15, 0.0, true, "estimated energy cost of the local GPU"),
            price("qwen3-0.6b", 0.02, 0.02, 0.0, true, "estimated energy cost of the local GPU"),
            price("summarizer", 0.15, 0.15, 0.0, true, "estimated energy cost of the local GPU"),
            price("claude-sonnet", 3.0, 15.0, 0.3, false, "demo price list"),
            price("router-qwen-coder", 0.4, 1.6, 0.0, false, "demo price list"),
        ];
        let client = |name: &str, project: &str, models: &[&str], mode: ConsentMode, daily: f64, rpm: u32| {
            let (_t, h, p) = new_client_token();
            ClientConfig {
                id: new_id(),
                name: name.into(),
                project: project.into(),
                token_hash: h,
                token_prefix: p,
                allowed_models: models.iter().map(|s| s.to_string()).collect(),
                consent_mode: mode,
                expires_at: Some((chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                daily_budget: daily,
                monthly_budget: 0.0,
                rpm_limit: rpm,
                revoked: false,
                created_at: now_rfc3339(),
            }
        };
        let mut analyst = client("API Analyst", "billing-api", &["foundry-gpt5-mini", "router-qwen-coder"], ConsentMode::Ask, 5.0, 30);
        analyst.token_hash = ask_hash.clone();
        analyst.token_prefix = ask_prefix.clone();
        v.config.clients = vec![
            client("VS Code - Code Reviewer", "payments-api", &["foundry-glm", "claude-sonnet"], ConsentMode::Session, 10.0, 60),
            analyst,
            client("Python batch", "data-pipeline", &["qwen-local", "gpt-oss-120b-cloud"], ConsentMode::Auto, 3.0, 120),
            client("Claude Code", "payments-api", &["claude-sonnet"], ConsentMode::Session, 15.0, 60),
        ];
        client_ids = v.config.clients.iter().map(|c| (c.id.clone(), c.name.clone(), c.project.clone())).collect();
        v.config.gateway.port = 8799; // keep clear of a real instance on 8765
        v.config.consent_rules.push(ConsentRule {
            id: new_id(),
            client_id: v.config.clients[0].id.clone(),
            model_alias: "foundry-glm".into(),
            created_at: now_rfc3339(),
            expires_at: None,
        });
        v.save()
    })?;

    // ---- 30 days of synthetic traffic
    let mut rng = rand::rng();
    let plans: [(&str, &str, &str, &str, usize, f64, f64, u64, u64); 6] = [
        // alias, provider, upstream, provider id, client idx, price in, price out, avg in, avg out
        ("foundry-glm", "Azure AI Foundry", "glm-4.6", "foundry", 0, 2.0, 8.0, 3800, 1100),
        ("claude-sonnet", "Anthropic", "claude-sonnet-5-5", "anthropic", 3, 3.0, 15.0, 5200, 900),
        ("foundry-gpt5-mini", "Azure AI Foundry", "gpt-5-mini", "foundry", 1, 0.25, 2.0, 2400, 700),
        ("router-qwen-coder", "OpenRouter", "qwen/qwen3-coder", "openrouter", 1, 0.4, 1.6, 3000, 800),
        ("qwen-local", "Ollama (local)", "qwen3:8b", "ollama-local", 2, 0.15, 0.15, 1800, 500),
        ("gpt-oss-120b-cloud", "Ollama Cloud", "gpt-oss:120b", "ollama-cloud", 2, 0.6, 2.4, 2600, 750),
    ];
    let agents = [["code-reviewer.agent", "copilot-chat"], ["api-analyst.agent", "notebook"], ["etl-summarizer", "nightly-report"], ["claude-code", "claude-code"]];
    for day in 0..30i64 {
        let weekday = (chrono::Utc::now() - chrono::Duration::days(day)).format("%u").to_string().parse::<u32>().unwrap_or(1);
        let load = if weekday >= 6 { 0.35 } else { 1.0 } * (1.0 + (29 - day) as f64 / 45.0);
        for (i, p) in plans.iter().enumerate() {
            let base = [26.0, 9.0, 14.0, 8.0, 22.0, 10.0][i];
            let n = (base * load * rng.random_range(0.7..1.3)) as usize;
            for _ in 0..n {
                let ts = chrono::Utc::now() - chrono::Duration::days(day) - chrono::Duration::seconds(rng.random_range(0..80_000));
                let (cid, cname, project) = client_ids[p.4].clone();
                let input = (p.7 as f64 * rng.random_range(0.3..1.9)) as u64;
                let output = (p.8 as f64 * rng.random_range(0.3..1.9)) as u64;
                let cached = if rng.random_bool(0.4) { input / 3 } else { 0 };
                let fail = rng.random_bool(0.025);
                let denied = !fail && rng.random_bool(0.015);
                let usage = if fail || denied {
                    Usage::default()
                } else {
                    Usage { input, output, cache_read: cached, cache_write: 0, reasoning: 0, source: if p.3 == "ollama-local" { UsageSource::Reported } else { UsageSource::Reported } }
                };
                let cost = (usage.input.saturating_sub(usage.cache_read) as f64 * p.5 + usage.output as f64 * p.6 + usage.cache_read as f64 * p.5 * 0.1) / 1e6;
                core.audit().record(&RequestRecord {
                    id: new_id(),
                    ts: ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    client_id: cid,
                    client_name: cname,
                    agent: agents[p.4][rng.random_range(0..2)].into(),
                    project,
                    endpoint: if p.0 == "claude-sonnet" && p.4 == 3 { "messages".into() } else { "chat.completions".into() },
                    model_alias: p.0.into(),
                    provider_id: p.3.into(),
                    provider_name: p.1.into(),
                    upstream_model: p.2.into(),
                    decision: if denied { "denied".into() } else { "allowed".into() },
                    decision_reason: if denied { "consent_denied".into() } else { "policy".into() },
                    consent: if denied { "denied".into() } else if p.4 == 2 { "auto".into() } else { ["session", "rule", "once"][rng.random_range(0..3)].into() },
                    status: if denied { 403 } else if fail { [429, 500, 503][rng.random_range(0..3)] } else { 200 },
                    error: if denied { "The vault owner denied this request.".into() } else if fail { "Upstream provider returned HTTP 429: rate limit".into() } else { String::new() },
                    latency_ms: if denied { 0 } else { rng.random_range(350..4200) },
                    usage,
                    cost: if fail || denied { 0.0 } else { cost },
                    currency: "USD".into(),
                    price_id: "demo".into(),
                    cost_estimated: p.3 == "ollama-local",
                    stream: rng.random_bool(0.6),
                })?;
            }
        }
    }
    for (kind, msg) in [
        ("vault", "demo vault created (synthetic data)"),
        ("provider", "provider 'Azure AI Foundry' saved"),
        ("client", "client token created: VS Code - Code Reviewer"),
        ("consent", "Always for VS Code - Code Reviewer / foundry-glm"),
        ("unlock_failed", "wrong master password (demo event)"),
    ] {
        core.audit().event(kind, msg);
    }
    core.restart_gateway()?;
    Ok(Demo { ask_token })
}

/// Fire a request from the "API Analyst" client so that a live consent prompt appears.
pub fn trigger_consent(core: &Arc<Core>, token: String) {
    let url = core.gateway_url().unwrap_or_else(|| "http://127.0.0.1:8765/v1".into());
    let http = reqwest::Client::new();
    core.rt.spawn(async move {
        let _ = http
            .post(format!("{url}/chat/completions"))
            .bearer_auth(token)
            .header("X-LLMVault-Agent", "api-analyst.agent")
            .header("X-LLMVault-Project", "billing-api")
            .json(&serde_json::json!({"model": "foundry-gpt5-mini", "messages": [{"role": "user", "content": "Summarize yesterday's API errors"}]}))
            .send()
            .await;
    });
}
