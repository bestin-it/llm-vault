//! The LLM gateway - the only network-facing surface of LLM Vault.
//!
//! Endpoints (all require a client token except /health):
//!   GET  /health
//!   GET  /v1/models
//!   POST /v1/chat/completions   (OpenAI format, streaming supported, any provider)
//!   POST /v1/messages           (Anthropic format, Anthropic + Ollama providers)
//!   POST /v1/embeddings         (OpenAI format, OpenAI-compatible providers)
//!
//! There is intentionally no endpoint that returns a provider key, a vault entry, a password
//! or the configuration. Clients can *use* a model; they cannot *read* a secret.

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::StreamExt;
use serde_json::{Value, json};

use crate::audit::RequestRecord;
use crate::config::{ProviderKind, new_id, now_rfc3339};
use crate::core::{Core, Plan};
use crate::policy::{Denial, hash_token};
use crate::pricing::{self, Usage, UsageSource};
use crate::providers::anthropic;

pub fn router(core: Arc<Core>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(messages))
        .route("/v1/embeddings", post(embeddings))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(32 * 1024 * 1024))
        .with_state(core)
}

// ------------------------------------------------------------------ helpers

fn client_token(h: &HeaderMap) -> Option<String> {
    if let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        return Some(v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")).unwrap_or(v).to_string());
    }
    h.get("x-api-key").or(h.get("api-key")).and_then(|v| v.to_str().ok()).map(String::from)
}

fn header_str(h: &HeaderMap, names: &[&str]) -> String {
    for n in names {
        if let Some(v) = h.get(*n).and_then(|v| v.to_str().ok()) {
            if !v.trim().is_empty() {
                return v.trim().chars().take(120).collect();
            }
        }
    }
    String::new()
}

fn agent_of(h: &HeaderMap, body: &Value) -> String {
    let a = header_str(h, &["x-llmvault-agent", "x-agent-name", "x-title"]);
    if !a.is_empty() {
        return a;
    }
    if let Some(u) = body["user"].as_str() {
        return u.chars().take(120).collect();
    }
    let ua = header_str(h, &["user-agent"]);
    ua.split_whitespace().next().unwrap_or("").to_string()
}

fn openai_error(status: u16, code: &str, message: &str) -> Response {
    let body = json!({"error": {"message": message, "type": code, "code": code}});
    (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), axum::Json(body)).into_response()
}

fn anthropic_error(status: u16, code: &str, message: &str) -> Response {
    let body = json!({"type": "error", "error": {"type": code, "message": message}});
    (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), axum::Json(body)).into_response()
}

/// Browsers send an Origin header; the gateway is for local tools and agents, so web pages
/// are refused to prevent drive-by use of a token from a malicious site (CSRF / DNS rebinding).
fn browser_origin(h: &HeaderMap) -> bool {
    match h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => false,
        Some(o) => !(o.starts_with("vscode-") || o == "null"),
    }
}

fn base_record(endpoint: &str, alias: &str, agent: String, project: String, stream: bool) -> RequestRecord {
    RequestRecord { id: new_id(), ts: now_rfc3339(), endpoint: endpoint.into(), model_alias: alias.into(), agent, project, stream, ..Default::default() }
}

fn denied(core: &Core, mut rec: RequestRecord, d: &Denial, client: Option<crate::config::ClientConfig>) {
    if let Some(c) = client {
        rec.client_id = c.id;
        rec.client_name = c.name;
        if rec.project.is_empty() {
            rec.project = c.project;
        }
    }
    rec.decision = "denied".into();
    rec.decision_reason = d.code().into();
    rec.consent = match d {
        Denial::ConsentDenied => "denied".into(),
        Denial::ConsentTimeout => "timeout".into(),
        _ => String::new(),
    };
    rec.status = d.status();
    rec.error = d.message();
    core.finish(rec);
}

fn fill_plan(rec: &mut RequestRecord, plan: &Plan) {
    rec.client_id = plan.client.id.clone();
    rec.client_name = plan.client.name.clone();
    if rec.project.is_empty() {
        rec.project = plan.client.project.clone();
    }
    rec.provider_id = plan.provider.id.clone();
    rec.provider_name = plan.provider.name.clone();
    rec.upstream_model = plan.model.upstream_model.clone();
    rec.decision = "allowed".into();
    rec.decision_reason = "policy".into();
    rec.consent = plan.consent.clone();
}

fn apply_cost(rec: &mut RequestRecord, usage: Usage, plan: &Plan) {
    rec.usage = usage;
    if let Some(p) = &plan.price {
        rec.cost = pricing::cost(&usage, p);
        rec.currency = p.currency.clone();
        rec.price_id = p.id.clone();
        rec.cost_estimated = p.estimated || usage.source != UsageSource::Reported;
    }
}

fn prompt_chars(req: &Value) -> usize {
    let mut n = 0;
    for m in req["messages"].as_array().into_iter().flatten() {
        n += match &m["content"] {
            Value::String(s) => s.len(),
            Value::Array(a) => a.iter().filter_map(|p| p["text"].as_str()).map(str::len).sum(),
            _ => 0,
        };
    }
    n + req["system"].as_str().map(str::len).unwrap_or(0)
}

/// Records the request when the response stream finishes *or* the client disconnects.
struct StreamAudit {
    core: Arc<Core>,
    rec: Option<RequestRecord>,
    plan_price: Option<crate::config::PriceVersion>,
    started: Instant,
    usage: Option<Usage>,
    prompt_chars: usize,
    completion_chars: usize,
    error: Option<String>,
}

impl Drop for StreamAudit {
    fn drop(&mut self) {
        if let Some(mut rec) = self.rec.take() {
            let usage = self.usage.unwrap_or_else(|| Usage::estimate(self.prompt_chars, self.completion_chars));
            rec.usage = usage;
            if let Some(p) = &self.plan_price {
                rec.cost = pricing::cost(&usage, p);
                rec.currency = p.currency.clone();
                rec.price_id = p.id.clone();
                rec.cost_estimated = p.estimated || usage.source != UsageSource::Reported;
            }
            rec.latency_ms = self.started.elapsed().as_millis() as u64;
            if let Some(e) = self.error.take() {
                rec.status = 502;
                rec.error = e;
            }
            self.core.finish(rec);
        }
    }
}

fn sse_response(stream: impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static) -> Response {
    let mut r = Response::new(Body::from_stream(stream));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    r
}

async fn upstream_failure(core: &Core, mut rec: RequestRecord, resp: reqwest::Response, started: Instant, anthropic_style: bool) -> Response {
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let msg = core.redact(&text.chars().take(2000).collect::<String>());
    rec.status = status;
    rec.error = msg.clone();
    rec.latency_ms = started.elapsed().as_millis() as u64;
    core.finish(rec);
    let detail = serde_json::from_str::<Value>(&msg).ok().and_then(|v| v["error"]["message"].as_str().map(String::from)).unwrap_or(msg);
    let m = format!("Upstream provider returned HTTP {status}: {detail}");
    if anthropic_style { anthropic_error(status, "upstream_error", &m) } else { openai_error(status, "upstream_error", &m) }
}

fn transport_failure(core: &Core, mut rec: RequestRecord, e: reqwest::Error, started: Instant, anthropic_style: bool) -> Response {
    let msg = core.redact(&format!("cannot reach provider: {}", e.without_url()));
    rec.status = 502;
    rec.error = msg.clone();
    rec.latency_ms = started.elapsed().as_millis() as u64;
    core.finish(rec);
    if anthropic_style { anthropic_error(502, "provider_unreachable", &msg) } else { openai_error(502, "provider_unreachable", &msg) }
}

// ----------------------------------------------------------------- handlers

async fn health(State(core): State<Arc<Core>>) -> Response {
    axum::Json(json!({"status": "ok", "service": "llm-vault", "version": env!("CARGO_PKG_VERSION"), "locked": !core.is_unlocked()})).into_response()
}

async fn not_found() -> Response {
    openai_error(404, "not_found", "Unknown endpoint. LLM Vault exposes /v1/models, /v1/chat/completions, /v1/messages and /v1/embeddings.")
}

async fn models(State(core): State<Arc<Core>>, headers: HeaderMap) -> Response {
    if browser_origin(&headers) {
        return openai_error(403, "browser_origin_refused", "Requests from web pages are not accepted.");
    }
    let Some(token) = client_token(&headers) else {
        return openai_error(401, "missing_token", &Denial::MissingToken.message());
    };
    let hash = hash_token(&token);
    let r = core.with_vault(|v| {
        let c = v.config.client_by_hash(&hash).filter(|c| !c.revoked)?;
        Some(
            v.config
                .models
                .iter()
                .filter(|m| m.enabled && (c.allowed_models.is_empty() || c.allowed_models.contains(&m.alias)))
                .map(|m| {
                    let owner = v.config.provider(&m.provider_id).map(|p| p.name.clone()).unwrap_or_default();
                    json!({"id": m.alias, "object": "model", "created": 0, "owned_by": owner, "description": m.description})
                })
                .collect::<Vec<_>>(),
        )
    });
    match r {
        None => openai_error(423, "vault_locked", &Denial::Locked.message()),
        Some(None) => openai_error(401, "invalid_token", &Denial::InvalidToken.message()),
        Some(Some(list)) => axum::Json(json!({"object": "list", "data": list})).into_response(),
    }
}

async fn chat_completions(State(core): State<Arc<Core>>, headers: HeaderMap, body: Bytes) -> Response {
    let started = Instant::now();
    if browser_origin(&headers) {
        return openai_error(403, "browser_origin_refused", "Requests from web pages are not accepted.");
    }
    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        return openai_error(400, "invalid_json", "Request body must be JSON.");
    };
    let alias = req["model"].as_str().unwrap_or("").to_string();
    let stream = req["stream"].as_bool().unwrap_or(false);
    let agent = agent_of(&headers, &req);
    let project = header_str(&headers, &["x-llmvault-project", "x-project"]);
    let mut rec = base_record("chat.completions", &alias, agent.clone(), project.clone(), stream);

    let plan = match core.authorize(client_token(&headers).as_deref(), &alias, &agent, &project).await {
        Ok(p) => p,
        Err((d, c)) => {
            let r = openai_error(d.status(), d.code(), &d.message());
            denied(&core, rec, &d, c);
            return r;
        }
    };
    fill_plan(&mut rec, &plan);

    if plan.provider.kind == ProviderKind::Anthropic {
        return anthropic_chat(core, plan, rec, req, stream, started).await;
    }

    let mut upstream_body = req.clone();
    upstream_body["model"] = json!(plan.model.upstream_model);
    if stream && upstream_body["stream_options"].is_null() {
        upstream_body["stream_options"] = json!({"include_usage": true});
    }
    let url = plan.upstream.chat_url(&plan.model.upstream_model);
    let resp = match plan.upstream.authorize(core.http.post(&url).json(&upstream_body)).send().await {
        Ok(r) => r,
        Err(e) => return transport_failure(&core, rec, e, started, false),
    };
    if !resp.status().is_success() {
        return upstream_failure(&core, rec, resp, started, false).await;
    }
    rec.status = 200;

    if !stream {
        let mut v: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return transport_failure(&core, rec, e, started, false),
        };
        let completion_chars = v["choices"][0]["message"]["content"].as_str().map(str::len).unwrap_or(0);
        let usage = Usage::from_openai(&v["usage"]).unwrap_or_else(|| Usage::estimate(prompt_chars(&req), completion_chars));
        v["model"] = json!(alias);
        apply_cost(&mut rec, usage, &plan);
        rec.latency_ms = started.elapsed().as_millis() as u64;
        core.finish(rec);
        return axum::Json(v).into_response();
    }

    // Streaming: re-frame SSE, rewrite the model name, capture usage.
    let client_wants_usage = req["stream_options"]["include_usage"].as_bool().unwrap_or(false);
    let mut audit = StreamAudit {
        core: core.clone(),
        rec: Some(rec),
        plan_price: plan.price.clone(),
        started,
        usage: None,
        prompt_chars: prompt_chars(&req),
        completion_chars: 0,
        error: None,
    };
    let mut up = resp.bytes_stream();
    let s = async_stream::stream! {
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = up.next().await {
            match chunk {
                Ok(b) => {
                    buf.extend_from_slice(&b);
                    while let Some(pos) = buf.iter().position(|c| *c == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line).trim().to_string();
                        let Some(data) = line.strip_prefix("data:").map(str::trim) else { continue };
                        if data == "[DONE]" {
                            yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: [DONE]\n\n"));
                            continue;
                        }
                        let Ok(mut v) = serde_json::from_str::<Value>(data) else { continue };
                        if let Some(u) = Usage::from_openai(&v["usage"]) {
                            audit.usage = Some(u);
                        }
                        if let Some(t) = v["choices"][0]["delta"]["content"].as_str() {
                            audit.completion_chars += t.len();
                        }
                        let usage_only = v["choices"].as_array().map(|a| a.is_empty()).unwrap_or(false);
                        if usage_only && !client_wants_usage {
                            continue;
                        }
                        v["model"] = json!(alias);
                        yield Ok(Bytes::from(format!("data: {v}\n\n")));
                    }
                }
                Err(e) => {
                    audit.error = Some(audit.core.redact(&format!("stream interrupted: {}", e.without_url())));
                    break;
                }
            }
        }
        drop(audit);
    };
    sse_response(s)
}

async fn anthropic_chat(core: Arc<Core>, plan: Plan, mut rec: RequestRecord, req: Value, stream: bool, started: Instant) -> Response {
    let body = anthropic::request_from_openai(&req, &plan.model.upstream_model);
    let url = plan.upstream.chat_url(&plan.model.upstream_model);
    let resp = match plan.upstream.authorize(core.http.post(&url).json(&body)).send().await {
        Ok(r) => r,
        Err(e) => return transport_failure(&core, rec, e, started, false),
    };
    if !resp.status().is_success() {
        return upstream_failure(&core, rec, resp, started, false).await;
    }
    rec.status = 200;
    let alias = rec.model_alias.clone();
    if !stream {
        let v: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return transport_failure(&core, rec, e, started, false),
        };
        let (out, usage) = anthropic::response_to_openai(&v, &alias);
        apply_cost(&mut rec, usage, &plan);
        rec.latency_ms = started.elapsed().as_millis() as u64;
        core.finish(rec);
        return axum::Json(out).into_response();
    }
    let client_wants_usage = req["stream_options"]["include_usage"].as_bool().unwrap_or(false);
    let mut audit = StreamAudit {
        core: core.clone(),
        rec: Some(rec),
        plan_price: plan.price.clone(),
        started,
        usage: None,
        prompt_chars: prompt_chars(&req),
        completion_chars: 0,
        error: None,
    };
    let mut conv = anthropic::StreamConverter::new(&alias);
    let mut up = resp.bytes_stream();
    let s = async_stream::stream! {
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = up.next().await {
            match chunk {
                Ok(b) => {
                    buf.extend_from_slice(&b);
                    while let Some(pos) = buf.iter().position(|c| *c == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line).trim().to_string();
                        let Some(data) = line.strip_prefix("data:").map(str::trim) else { continue };
                        let Ok(ev) = serde_json::from_str::<Value>(data) else { continue };
                        for c in conv.feed(&ev) {
                            yield Ok::<Bytes, std::io::Error>(Bytes::from(format!("data: {c}\n\n")));
                        }
                        if ev["type"] == "message_stop" {
                            if client_wants_usage {
                                yield Ok(Bytes::from(format!("data: {}\n\n", conv.usage_chunk())));
                            }
                            yield Ok(Bytes::from_static(b"data: [DONE]\n\n"));
                        }
                    }
                }
                Err(e) => {
                    audit.error = Some(audit.core.redact(&format!("stream interrupted: {}", e.without_url())));
                    break;
                }
            }
        }
        audit.completion_chars = conv.text_len;
        if conv.usage.source == UsageSource::Reported {
            audit.usage = Some(conv.usage);
        }
        drop(audit);
    };
    sse_response(s)
}

/// Native Anthropic Messages API (Claude Code, Anthropic SDKs). Passed through to Anthropic or
/// to Ollama's Anthropic-compatible endpoint.
async fn messages(State(core): State<Arc<Core>>, headers: HeaderMap, body: Bytes) -> Response {
    let started = Instant::now();
    if browser_origin(&headers) {
        return anthropic_error(403, "permission_error", "Requests from web pages are not accepted.");
    }
    let Ok(mut req) = serde_json::from_slice::<Value>(&body) else {
        return anthropic_error(400, "invalid_request_error", "Request body must be JSON.");
    };
    let alias = req["model"].as_str().unwrap_or("").to_string();
    let stream = req["stream"].as_bool().unwrap_or(false);
    let agent = agent_of(&headers, &req);
    let project = header_str(&headers, &["x-llmvault-project", "x-project"]);
    let mut rec = base_record("messages", &alias, agent.clone(), project.clone(), stream);

    let plan = match core.authorize(client_token(&headers).as_deref(), &alias, &agent, &project).await {
        Ok(p) => p,
        Err((d, c)) => {
            let r = anthropic_error(d.status(), d.code(), &d.message());
            denied(&core, rec, &d, c);
            return r;
        }
    };
    fill_plan(&mut rec, &plan);
    let Some(url) = plan.upstream.messages_url() else {
        let d = Denial::UnsupportedEndpoint(format!(
            "Model '{alias}' is served by an OpenAI-compatible provider; use /v1/chat/completions for it."
        ));
        let r = anthropic_error(400, "invalid_request_error", &d.message());
        rec.status = 400;
        rec.error = d.message();
        core.finish(rec);
        return r;
    };
    req["model"] = json!(plan.model.upstream_model);
    let mut rb = core.http.post(&url).json(&req);
    if let Some(b) = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()) {
        rb = rb.header("anthropic-beta", b);
    }
    let resp = match plan.upstream.authorize(rb).send().await {
        Ok(r) => r,
        Err(e) => return transport_failure(&core, rec, e, started, true),
    };
    if !resp.status().is_success() {
        return upstream_failure(&core, rec, resp, started, true).await;
    }
    rec.status = 200;
    if !stream {
        let mut v: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return transport_failure(&core, rec, e, started, true),
        };
        let usage = anthropic::usage_from_anthropic(&v["usage"]);
        v["model"] = json!(alias);
        apply_cost(&mut rec, usage, &plan);
        rec.latency_ms = started.elapsed().as_millis() as u64;
        core.finish(rec);
        return axum::Json(v).into_response();
    }
    let mut audit = StreamAudit {
        core: core.clone(),
        rec: Some(rec),
        plan_price: plan.price.clone(),
        started,
        usage: None,
        prompt_chars: prompt_chars(&req),
        completion_chars: 0,
        error: None,
    };
    let mut up = resp.bytes_stream();
    let s = async_stream::stream! {
        let mut buf: Vec<u8> = Vec::new();
        let mut usage = Usage { source: UsageSource::Unavailable, ..Default::default() };
        while let Some(chunk) = up.next().await {
            match chunk {
                Ok(b) => {
                    buf.extend_from_slice(&b);
                    while let Some(pos) = buf.iter().position(|c| *c == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        if let Some(data) = String::from_utf8_lossy(&line).trim().strip_prefix("data:") {
                            if let Ok(ev) = serde_json::from_str::<Value>(data.trim()) {
                                match ev["type"].as_str() {
                                    Some("message_start") => {
                                        let u = anthropic::usage_from_anthropic(&ev["message"]["usage"]);
                                        usage.input = u.input; usage.cache_read = u.cache_read; usage.cache_write = u.cache_write;
                                        usage.source = UsageSource::Reported;
                                    }
                                    Some("message_delta") => {
                                        if let Some(o) = ev["usage"]["output_tokens"].as_u64() { usage.output = o; }
                                    }
                                    Some("content_block_delta") => {
                                        audit.completion_chars += ev["delta"]["text"].as_str().map(str::len).unwrap_or(0);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        yield Ok::<Bytes, std::io::Error>(Bytes::from(line));
                    }
                }
                Err(e) => {
                    audit.error = Some(audit.core.redact(&format!("stream interrupted: {}", e.without_url())));
                    break;
                }
            }
        }
        if !buf.is_empty() { yield Ok(Bytes::from(std::mem::take(&mut buf))); }
        if usage.source == UsageSource::Reported { audit.usage = Some(usage); }
        drop(audit);
    };
    sse_response(s)
}

async fn embeddings(State(core): State<Arc<Core>>, headers: HeaderMap, body: Bytes) -> Response {
    let started = Instant::now();
    if browser_origin(&headers) {
        return openai_error(403, "browser_origin_refused", "Requests from web pages are not accepted.");
    }
    let Ok(mut req) = serde_json::from_slice::<Value>(&body) else {
        return openai_error(400, "invalid_json", "Request body must be JSON.");
    };
    let alias = req["model"].as_str().unwrap_or("").to_string();
    let agent = agent_of(&headers, &req);
    let project = header_str(&headers, &["x-llmvault-project", "x-project"]);
    let mut rec = base_record("embeddings", &alias, agent.clone(), project.clone(), false);
    let plan = match core.authorize(client_token(&headers).as_deref(), &alias, &agent, &project).await {
        Ok(p) => p,
        Err((d, c)) => {
            let r = openai_error(d.status(), d.code(), &d.message());
            denied(&core, rec, &d, c);
            return r;
        }
    };
    fill_plan(&mut rec, &plan);
    let Some(url) = plan.upstream.embeddings_url(&plan.model.upstream_model) else {
        rec.status = 400;
        rec.error = "provider does not support embeddings".into();
        core.finish(rec);
        return openai_error(400, "unsupported_endpoint", "This provider does not offer embeddings.");
    };
    req["model"] = json!(plan.model.upstream_model);
    let resp = match plan.upstream.authorize(core.http.post(&url).json(&req)).send().await {
        Ok(r) => r,
        Err(e) => return transport_failure(&core, rec, e, started, false),
    };
    if !resp.status().is_success() {
        return upstream_failure(&core, rec, resp, started, false).await;
    }
    rec.status = 200;
    let mut v: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return transport_failure(&core, rec, e, started, false),
    };
    let chars = match &req["input"] {
        Value::String(s) => s.len(),
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).map(str::len).sum(),
        _ => 0,
    };
    let usage = Usage::from_openai(&v["usage"]).unwrap_or_else(|| Usage::estimate(chars, 0));
    v["model"] = json!(alias);
    apply_cost(&mut rec, usage, &plan);
    rec.latency_ms = started.elapsed().as_millis() as u64;
    core.finish(rec);
    axum::Json(v).into_response()
}
