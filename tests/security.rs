//! End-to-end security & acceptance tests for the gateway, against a mock provider.
//!
//! Acceptance criteria covered (from the product concept):
//!  * an agent has no API that returns a provider secret;
//!  * unauthorized requests are rejected; consent can be denied / revoked;
//!  * locking the vault invalidates access to protected secrets;
//!  * errors and logs do not reveal keys (leak tests).

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};

use llmvault::audit::Filter;
use llmvault::config::{AuthStyle, ClientConfig, ConsentMode, ModelAlias, PriceVersion, ProviderConfig, ProviderKind, new_id, now_rfc3339};
use llmvault::core::Core;
use llmvault::policy::{ConsentDecision, new_client_token};

const KEY: &str = "sk-test-UPSTREAM-SECRET-0123456789abcdef";
const ANT_KEY: &str = "sk-ant-test-ANTHROPIC-SECRET-0123456789";
const PASSWORD: &str = "correct horse battery staple";

async fn mock_chat(headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if auth != format!("Bearer {KEY}") {
        return (axum::http::StatusCode::UNAUTHORIZED, axum::Json(json!({"error": {"message": format!("Incorrect API key provided: {auth}")}}))).into_response();
    }
    let req: Value = serde_json::from_slice(&body).unwrap();
    if req["model"] == "upstream-fail" {
        // A careless provider that echoes the key in its error message.
        return (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"error": {"message": format!("bad request for key {KEY}")}}))).into_response();
    }
    if req["stream"].as_bool().unwrap_or(false) {
        let model = req["model"].as_str().unwrap().to_string();
        let mut s = String::new();
        for t in ["Hel", "lo"] {
            s.push_str(&format!("data: {}\n\n", json!({"id":"x","object":"chat.completion.chunk","model":model,"choices":[{"index":0,"delta":{"content":t},"finish_reason":null}]})));
        }
        s.push_str(&format!("data: {}\n\n", json!({"id":"x","object":"chat.completion.chunk","model":model,"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13}})));
        s.push_str("data: [DONE]\n\n");
        return ([("content-type", "text/event-stream")], s).into_response();
    }
    axum::Json(json!({
        "id": "chatcmpl-1", "object": "chat.completion", "model": req["model"],
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello from upstream"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .into_response()
}

async fn mock_messages(headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let key = headers.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    if key != ANT_KEY {
        return (axum::http::StatusCode::UNAUTHORIZED, "bad key").into_response();
    }
    let req: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(req["system"], "be brief");
    axum::Json(json!({"id": "msg_1", "type": "message", "role": "assistant", "model": req["model"],
        "content": [{"type": "text", "text": "Hi from Claude"}], "stop_reason": "end_turn",
        "usage": {"input_tokens": 20, "output_tokens": 4}}))
    .into_response()
}

async fn start_mock() -> String {
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_chat))
        .route("/v1/messages", post(mock_messages))
        .route("/v1/models", get(|| async { axum::Json(json!({"data": [{"id": "m1"}, {"id": "m2"}]})) }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

struct Env {
    core: Arc<Core>,
    gw: String,
    token: String,
    client_id: String,
    vault_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn setup(mode: ConsentMode) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let core = Core::new_for_tests(dir.path(), tokio::runtime::Handle::current());
    let vault_path = dir.path().join("test.kdbx");
    core.create_vault(&vault_path, PASSWORD, None).unwrap();
    let mock = start_mock().await;
    let (token, hash, prefix) = new_client_token();
    let client_id = new_id();
    let cid = client_id.clone();
    core.with_vault_mut(|v| {
        let secret = v.set_provider_secret(None, "Mock OpenAI", &mock, KEY)?;
        let ant = v.set_provider_secret(None, "Mock Anthropic", &mock, ANT_KEY)?;
        v.config.gateway.port = 0;
        v.config.gateway.consent_timeout_s = 5;
        v.config.providers.push(ProviderConfig {
            id: "p1".into(),
            name: "Mock OpenAI".into(),
            preset: "openai-compatible".into(),
            kind: ProviderKind::OpenAi,
            base_url: format!("{mock}/v1"),
            auth: AuthStyle::Bearer,
            secret_entry: Some(secret),
            api_version: None,
            allow_http: false,
            enabled: true,
            created_at: now_rfc3339(),
        });
        v.config.providers.push(ProviderConfig {
            id: "p2".into(),
            name: "Mock Anthropic".into(),
            preset: "anthropic".into(),
            kind: ProviderKind::Anthropic,
            base_url: mock.clone(),
            auth: AuthStyle::XApiKey,
            secret_entry: Some(ant),
            api_version: None,
            allow_http: false,
            enabled: true,
            created_at: now_rfc3339(),
        });
        for (alias, prov, up) in [("foundry-glm", "p1", "glm-4.6"), ("broken", "p1", "upstream-fail"), ("claude", "p2", "claude-sonnet"), ("secret-model", "p1", "x")] {
            v.config.models.push(ModelAlias { alias: alias.into(), provider_id: prov.into(), upstream_model: up.into(), description: String::new(), enabled: true });
        }
        v.config.prices.push(PriceVersion {
            id: "price1".into(),
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
        });
        v.config.clients.push(ClientConfig {
            id: cid,
            name: "Code Reviewer".into(),
            project: "demo".into(),
            token_hash: hash,
            token_prefix: prefix,
            allowed_models: vec!["foundry-glm".into(), "broken".into(), "claude".into()],
            consent_mode: mode,
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
    let gw = core.start_gateway().unwrap().trim_end_matches("/v1").to_string();
    Env { core, gw, token, client_id, vault_path, _dir: dir }
}

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

async fn chat(env: &Env, token: &str, model: &str, stream: bool) -> (u16, String) {
    let r = http()
        .post(format!("{}/v1/chat/completions", env.gw))
        .bearer_auth(token)
        .header("x-llmvault-agent", "test-agent")
        .json(&json!({"model": model, "stream": stream, "messages": [{"role": "user", "content": "Review code"}]}))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

fn audit_dump(env: &Env) -> String {
    serde_json::to_string(&env.core.audit().requests(&Filter::default(), 1000)).unwrap() + &format!("{:?}", env.core.audit().events(1000))
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_request_works_counts_tokens_and_cost() {
    let env = setup(ConsentMode::Auto).await;
    let (st, body) = chat(&env, &env.token, "foundry-glm", false).await;
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["choices"][0]["message"]["content"], "Hello from upstream");
    assert_eq!(v["model"], "foundry-glm", "upstream model name must be replaced by the alias");
    let rows = env.core.audit().requests(&Filter::default(), 10);
    assert_eq!(rows[0].usage.input, 1000);
    assert_eq!(rows[0].usage.source.as_str(), "reported");
    assert!((rows[0].cost - (1000.0 * 2.0 + 500.0 * 8.0) / 1e6).abs() < 1e-12);
    assert_eq!(rows[0].agent, "test-agent");
    assert_eq!(rows[0].consent, "auto");
}

#[tokio::test(flavor = "multi_thread")]
async fn streaming_is_reframed_and_usage_recorded() {
    let env = setup(ConsentMode::Auto).await;
    let (st, body) = chat(&env, &env.token, "foundry-glm", true).await;
    assert_eq!(st, 200);
    assert!(body.contains("\"Hel\"") && body.contains("\"lo\""), "{body}");
    assert!(body.contains("[DONE]"));
    assert!(!body.contains("glm-4.6"), "upstream model must not leak: {body}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rows = env.core.audit().requests(&Filter::default(), 10);
    assert_eq!(rows[0].usage.input, 11);
    assert_eq!(rows[0].usage.output, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_endpoint_returns_a_secret() {
    let env = setup(ConsentMode::Auto).await;
    let probes = [
        "/v1/secrets", "/v1/keys", "/v1/config", "/v1/providers", "/v1/entries", "/api/vault", "/admin", "/v1/models", "/health",
        "/v1/models/foundry-glm", "/v1/vault/export", "/debug",
    ];
    for p in probes {
        for method in ["GET", "POST"] {
            let r = http()
                .request(method.parse().unwrap(), format!("{}{}", env.gw, p))
                .bearer_auth(&env.token)
                .json(&json!({"model": "foundry-glm"}))
                .send()
                .await
                .unwrap();
            let body = r.text().await.unwrap();
            assert!(!body.contains(KEY) && !body.contains(ANT_KEY) && !body.contains(PASSWORD), "{method} {p} leaked: {body}");
        }
    }
    let (_, body) = chat(&env, &env.token, "foundry-glm", false).await;
    assert!(!body.contains(KEY));
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_requests_are_rejected() {
    let env = setup(ConsentMode::Auto).await;
    let r = http().post(format!("{}/v1/chat/completions", env.gw)).json(&json!({"model": "foundry-glm", "messages": []})).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let (st, _) = chat(&env, "lvk_not-a-real-token-123456", "foundry-glm", false).await;
    assert_eq!(st, 401);
    let (st, body) = chat(&env, &env.token, "secret-model", false).await;
    assert_eq!(st, 403, "{body}");
    let (st, _) = chat(&env, &env.token, "does-not-exist", false).await;
    assert_eq!(st, 404);
    // Browser pages are refused even with a valid token.
    let r = http()
        .post(format!("{}/v1/chat/completions", env.gw))
        .bearer_auth(&env.token)
        .header("origin", "https://evil.example")
        .json(&json!({"model": "foundry-glm", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_token_is_rejected() {
    let env = setup(ConsentMode::Auto).await;
    let id = env.client_id.clone();
    env.core
        .with_vault_mut(|v| {
            v.config.clients.iter_mut().find(|c| c.id == id).unwrap().revoked = true;
            v.save()
        })
        .unwrap();
    let (st, body) = chat(&env, &env.token, "foundry-glm", false).await;
    assert_eq!(st, 401);
    assert!(body.contains("token_revoked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_the_vault_blocks_the_gateway() {
    let env = setup(ConsentMode::Auto).await;
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 200);
    env.core.lock("test");
    let (st, body) = chat(&env, &env.token, "foundry-glm", false).await;
    assert_eq!(st, 423, "{body}");
    assert!(body.contains("vault_locked"));
    env.core.unlock(&env.vault_path, PASSWORD, None).unwrap();
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_errors_and_audit_never_contain_the_key() {
    let env = setup(ConsentMode::Auto).await;
    let (st, body) = chat(&env, &env.token, "broken", false).await;
    assert_eq!(st, 400);
    assert!(!body.contains(KEY), "client saw the key: {body}");
    assert!(body.contains("[REDACTED]"), "{body}");
    let dump = audit_dump(&env);
    assert!(!dump.contains(KEY) && !dump.contains(ANT_KEY), "audit leaked a key");
    // The audit database file itself must not contain the key either.
    let db = std::fs::read(env.core.paths().audit_db()).unwrap_or_default();
    assert!(!String::from_utf8_lossy(&db).contains(KEY));
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_file_is_encrypted_and_password_protected() {
    let env = setup(ConsentMode::Auto).await;
    let bytes = std::fs::read(&env.vault_path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(KEY) && !text.contains("Mock OpenAI") && !text.contains("foundry-glm"));
    assert_eq!(&bytes[..4], &[0x03, 0xD9, 0xA2, 0x9A], "KDBX signature");
    env.core.lock("test");
    assert!(env.core.unlock(&env.vault_path, "wrong password!", None).is_err());
    assert!(env.core.unlock(&env.vault_path, PASSWORD, None).is_ok());
    // Configuration survived the round trip (it lives inside the encrypted file).
    assert_eq!(env.core.with_vault(|v| v.config.models.len()).unwrap(), 4);
}

async fn wait_pending(core: &Core) -> String {
    for _ in 0..200 {
        if let Some(p) = core.pending_consents().first() {
            return p.id.clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no consent request appeared");
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_deny_once_session() {
    let env = Arc::new(setup(ConsentMode::Ask).await);

    // Deny
    let e = env.clone();
    let h = tokio::spawn(async move { chat(&e, &e.token, "foundry-glm", false).await });
    let id = wait_pending(&env.core).await;
    env.core.resolve_consent(&id, ConsentDecision::Deny);
    let (st, body) = h.await.unwrap();
    assert_eq!(st, 403, "{body}");
    assert!(body.contains("consent_denied"));

    // Allow once - the next request asks again
    let e = env.clone();
    let h = tokio::spawn(async move { chat(&e, &e.token, "foundry-glm", false).await });
    let id = wait_pending(&env.core).await;
    env.core.resolve_consent(&id, ConsentDecision::Once);
    assert_eq!(h.await.unwrap().0, 200);

    // Allow for session - subsequent requests pass without a prompt
    let e = env.clone();
    let h = tokio::spawn(async move { chat(&e, &e.token, "foundry-glm", false).await });
    let id = wait_pending(&env.core).await;
    env.core.resolve_consent(&id, ConsentDecision::Session);
    assert_eq!(h.await.unwrap().0, 200);
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 200);

    // Revoking the session grant brings the prompt back; locking clears all grants.
    env.core.revoke_session_grant(&env.client_id, "foundry-glm");
    assert!(env.core.session_grants().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_timeout_denies() {
    let env = setup(ConsentMode::Ask).await;
    env.core
        .with_vault_mut(|v| {
            v.config.gateway.consent_timeout_s = 1;
            v.save()
        })
        .unwrap();
    let (st, body) = chat(&env, &env.token, "foundry-glm", false).await;
    assert_eq!(st, 403);
    assert!(body.contains("consent_timeout"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_and_budget() {
    let env = setup(ConsentMode::Auto).await;
    let id = env.client_id.clone();
    env.core
        .with_vault_mut(|v| {
            let c = v.config.clients.iter_mut().find(|c| c.id == id).unwrap();
            c.rpm_limit = 2;
            v.save()
        })
        .unwrap();
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 200);
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 200);
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 429);

    let env = setup(ConsentMode::Auto).await;
    let id = env.client_id.clone();
    env.core
        .with_vault_mut(|v| {
            v.config.clients.iter_mut().find(|c| c.id == id).unwrap().daily_budget = 0.001;
            v.save()
        })
        .unwrap();
    assert_eq!(chat(&env, &env.token, "foundry-glm", false).await.0, 200); // costs 0.006 USD
    let (st, body) = chat(&env, &env.token, "foundry-glm", false).await;
    assert_eq!(st, 429);
    assert!(body.contains("budget_exceeded"));
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_client_can_use_anthropic_provider() {
    let env = setup(ConsentMode::Auto).await;
    let r = http()
        .post(format!("{}/v1/chat/completions", env.gw))
        .bearer_auth(&env.token)
        .json(&json!({"model": "claude", "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["choices"][0]["message"]["content"], "Hi from Claude");
    assert_eq!(v["usage"]["prompt_tokens"], 20);
    // Native Anthropic endpoint with x-api-key = client token (Claude Code style)
    let r = http()
        .post(format!("{}/v1/messages", env.gw))
        .header("x-api-key", &env.token)
        .json(&json!({"model": "claude", "max_tokens": 10, "system": "be brief", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["model"], "claude");
}

#[tokio::test(flavor = "multi_thread")]
async fn models_lists_only_allowed_aliases() {
    let env = setup(ConsentMode::Auto).await;
    let r = http().get(format!("{}/v1/models", env.gw)).bearer_auth(&env.token).send().await.unwrap();
    let v: Value = r.json().await.unwrap();
    let ids: Vec<&str> = v["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"foundry-glm") && !ids.contains(&"secret-model"));
}
