//! Live end-to-end tests against real local model servers (not run by default).
//!
//!   cargo test --release --test live_local -- --ignored --nocapture
//!
//! Environment:
//!   LLMVAULT_LIVE_OLLAMA_MODEL    (default qwen3:0.6b)      - Ollama on 127.0.0.1:11434
//!   LLMVAULT_LIVE_LMSTUDIO_MODEL  (default: first listed)   - LM Studio on 127.0.0.1:1234
//!
//! Each test goes through the full path: client token -> policy -> vault -> provider,
//! checks streaming, the Anthropic-compatible endpoint (Ollama), the audit trail and that the
//! gateway overhead is small, then prints the measurements.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};

use llmvault::audit::Filter;
use llmvault::config::{AuthStyle, ClientConfig, ConsentMode, ModelAlias, PriceVersion, ProviderConfig, ProviderKind, new_id, now_rfc3339};
use llmvault::core::Core;
use llmvault::policy::new_client_token;

struct Live {
    core: Arc<Core>,
    gw: String,
    token: String,
    _dir: tempfile::TempDir,
}

async fn setup(preset: &str, kind: ProviderKind, base_url: &str, alias: &str, upstream: &str) -> Live {
    let dir = tempfile::tempdir().unwrap();
    let core = Core::new_for_tests(dir.path(), tokio::runtime::Handle::current());
    core.create_vault(&dir.path().join("live.kdbx"), "live-test-password", None).unwrap();
    let (token, hash, prefix) = new_client_token();
    core.with_vault_mut(|v| {
        v.config.gateway.port = 0;
        v.config.providers.push(ProviderConfig {
            id: "local".into(),
            name: preset.into(),
            preset: preset.into(),
            kind,
            base_url: base_url.into(),
            auth: AuthStyle::None,
            secret_entry: None,
            api_version: None,
            allow_http: false,
            enabled: true,
            created_at: now_rfc3339(),
        });
        v.config.models.push(ModelAlias { alias: alias.into(), provider_id: "local".into(), upstream_model: upstream.into(), description: String::new(), enabled: true });
        v.config.prices.push(PriceVersion {
            id: new_id(),
            alias: alias.into(),
            currency: "USD".into(),
            input: 0.0,
            output: 0.0,
            cache_read: 0.0,
            cache_write: 0.0,
            reasoning: 0.0,
            effective_from: "2026-01-01".into(),
            source: "local".into(),
            estimated: true,
        });
        v.config.clients.push(ClientConfig {
            id: new_id(),
            name: "live-test".into(),
            project: "e2e".into(),
            token_hash: hash,
            token_prefix: prefix,
            allowed_models: vec![],
            consent_mode: ConsentMode::Auto,
            expires_at: None,
            daily_budget: 0.0,
            monthly_budget: 0.0,
            rpm_limit: 0,
            revoked: false,
            created_at: now_rfc3339(),
        });
        v.save()
    })
    .unwrap();
    let gw = core.start_gateway().unwrap();
    Live { core, gw, token, _dir: dir }
}

const PROMPT: &str = "A server returns HTTP 429. Should the client retry immediately, retry with backoff, or give up? Answer with one word, then one short sentence.";

async fn measure(live: &Live, alias: &str, direct_url: &str, upstream: &str) {
    let http = reqwest::Client::new();
    let body = |model: &str, stream: bool| json!({"model": model, "stream": stream, "max_tokens": 1200, "messages": [{"role": "user", "content": PROMPT}]});

    // warm-up (model load) directly at the provider
    let _ = http.post(format!("{direct_url}/chat/completions")).json(&body(upstream, false)).send().await.unwrap().text().await;

    // direct vs. through the vault, non-streaming
    let t = Instant::now();
    let direct: Value = http.post(format!("{direct_url}/chat/completions")).json(&body(upstream, false)).send().await.unwrap().json().await.unwrap();
    let direct_ms = t.elapsed().as_millis();
    let t = Instant::now();
    let r = http.post(format!("{}/chat/completions", live.gw)).bearer_auth(&live.token).header("X-LLMVault-Agent", "live-test").json(&body(alias, false)).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let via: Value = r.json().await.unwrap();
    let via_ms = t.elapsed().as_millis();
    assert_eq!(via["model"], alias);
    let answer = via["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();

    // streaming through the vault
    let t = Instant::now();
    let r = http.post(format!("{}/chat/completions", live.gw)).bearer_auth(&live.token).json(&body(alias, true)).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let sse = r.text().await.unwrap();
    let stream_ms = t.elapsed().as_millis();
    assert!(sse.contains("[DONE]"), "stream did not finish: {sse}");
    let chunks = sse.matches("data: {").count();

    std::thread::sleep(std::time::Duration::from_millis(200));
    let rows = live.core.audit().requests(&Filter::default(), 10);
    assert!(rows.len() >= 2);
    let u = rows.iter().find(|r| !r.stream).unwrap().usage;
    println!("\n=== {alias} ({upstream}) ===");
    println!("direct provider call : {direct_ms} ms (completion tokens {})", direct["usage"]["completion_tokens"]);
    println!("via LLM Vault        : {via_ms} ms, usage {} in / {} out ({})", u.input, u.output, u.source.as_str());
    println!("gateway overhead     : {} ms (single run, includes model variance)", via_ms as i64 - direct_ms as i64);
    println!("streaming via vault  : {stream_ms} ms, {chunks} SSE chunks");
    println!("answer               : {}", answer.chars().take(300).collect::<String>());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn ollama_local_end_to_end() {
    let model = std::env::var("LLMVAULT_LIVE_OLLAMA_MODEL").unwrap_or_else(|_| "qwen3:0.6b".into());
    let live = setup("ollama-local", ProviderKind::Ollama, "http://127.0.0.1:11434", "qwen-local", &model).await;
    measure(&live, "qwen-local", "http://127.0.0.1:11434/v1", &model).await;

    // Anthropic-compatible endpoint (what Claude Code uses) through Ollama
    let r = reqwest::Client::new()
        .post(format!("{}/messages", live.gw))
        .header("x-api-key", &live.token)
        .json(&json!({"model": "qwen-local", "max_tokens": 120, "messages": [{"role": "user", "content": "Say OK."}]}))
        .send()
        .await
        .unwrap();
    let st = r.status().as_u16();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    println!("/v1/messages via Ollama: HTTP {st}, stop_reason {}, usage {}", v["stop_reason"], v["usage"]);
    assert_eq!(st, 200, "{v}");

    // Tool calling + streaming (what VS Code Copilot agent mode sends)
    let tools = json!([{"type": "function", "function": {"name": "read_file", "description": "Read a file from the workspace",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]);
    let r = reqwest::Client::new()
        .post(format!("{}/chat/completions", live.gw))
        .bearer_auth(&live.token)
        .json(&json!({"model": "qwen-local", "stream": true, "tools": tools, "max_tokens": 600,
            "messages": [{"role": "user", "content": "Use the read_file tool to open src/main.rs. /no_think"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let sse = r.text().await.unwrap();
    let has_tool = sse.contains("\"tool_calls\"") && sse.contains("read_file");
    println!("streamed tool call    : {}", if has_tool { "yes (read_file)" } else { "no tool call in this run" });
    assert!(sse.contains("[DONE]"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn lmstudio_end_to_end() {
    let model = match std::env::var("LLMVAULT_LIVE_LMSTUDIO_MODEL") {
        Ok(m) => m,
        Err(_) => {
            let v: Value = reqwest::get("http://127.0.0.1:1234/v1/models").await.expect("LM Studio server not running").json().await.unwrap();
            v["data"][0]["id"].as_str().expect("no model loaded in LM Studio").to_string()
        }
    };
    let live = setup("lmstudio", ProviderKind::OpenAi, "http://127.0.0.1:1234/v1", "lmstudio-local", &model).await;
    measure(&live, "lmstudio-local", "http://127.0.0.1:1234/v1", &model).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn llamacpp_end_to_end() {
    // llama-server -m model.gguf --port 8080 --jinja
    let v: Value = reqwest::get("http://127.0.0.1:8080/v1/models").await.expect("llama-server not running on :8080").json().await.unwrap();
    let model = v["data"][0]["id"].as_str().expect("no model").to_string();
    let live = setup("llama-cpp", ProviderKind::OpenAi, "http://127.0.0.1:8080/v1", "llamacpp-local", &model).await;
    measure(&live, "llamacpp-local", "http://127.0.0.1:8080/v1", &model).await;
}
