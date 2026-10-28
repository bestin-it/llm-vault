//! Translation between the OpenAI Chat Completions format and the Anthropic Messages API.

use serde_json::{Map, Value, json};

use crate::pricing::{Usage, UsageSource};

fn content_to_blocks(content: &Value) -> Vec<Value> {
    match content {
        Value::String(s) => vec![json!({"type": "text", "text": s})],
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| match p["type"].as_str() {
                Some("text") => Some(json!({"type": "text", "text": p["text"].as_str().unwrap_or("")})),
                Some("image_url") => {
                    let url = p["image_url"]["url"].as_str().unwrap_or("");
                    if let Some(rest) = url.strip_prefix("data:") {
                        let (meta, data) = rest.split_once(',')?;
                        let media = meta.trim_end_matches(";base64");
                        Some(json!({"type": "image", "source": {"type": "base64", "media_type": media, "data": data}}))
                    } else {
                        Some(json!({"type": "image", "source": {"type": "url", "url": url}}))
                    }
                }
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn content_to_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts.iter().filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

/// Convert an OpenAI chat completion request into an Anthropic Messages request.
pub fn request_from_openai(req: &Value, upstream_model: &str) -> Value {
    let mut system: Vec<String> = Vec::new();
    let mut messages: Vec<Value> = Vec::new();

    let push = |role: &str, blocks: Vec<Value>, messages: &mut Vec<Value>| {
        if blocks.is_empty() {
            return;
        }
        if let Some(last) = messages.last_mut() {
            if last["role"] == role {
                if let Some(arr) = last["content"].as_array_mut() {
                    arr.extend(blocks);
                    return;
                }
            }
        }
        messages.push(json!({"role": role, "content": blocks}));
    };

    for m in req["messages"].as_array().cloned().unwrap_or_default() {
        match m["role"].as_str().unwrap_or("user") {
            "system" | "developer" => system.push(content_to_text(&m["content"])),
            "assistant" => {
                let mut blocks = content_to_blocks(&m["content"]);
                blocks.retain(|b| b["type"] != "text" || b["text"].as_str().map(|t| !t.is_empty()).unwrap_or(false));
                for tc in m["tool_calls"].as_array().cloned().unwrap_or_default() {
                    let args = tc["function"]["arguments"].as_str().unwrap_or("{}");
                    let input: Value = serde_json::from_str(args).unwrap_or(json!({}));
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": tc["id"].as_str().unwrap_or("toolu_0"),
                        "name": tc["function"]["name"].as_str().unwrap_or(""),
                        "input": input
                    }));
                }
                push("assistant", blocks, &mut messages);
            }
            "tool" => {
                let block = json!({
                    "type": "tool_result",
                    "tool_use_id": m["tool_call_id"].as_str().unwrap_or(""),
                    "content": content_to_text(&m["content"])
                });
                push("user", vec![block], &mut messages);
            }
            _ => push("user", content_to_blocks(&m["content"]), &mut messages),
        }
    }

    let max_tokens = req["max_completion_tokens"].as_u64().or(req["max_tokens"].as_u64()).unwrap_or(4096);
    let mut out = Map::new();
    out.insert("model".into(), json!(upstream_model));
    out.insert("max_tokens".into(), json!(max_tokens));
    out.insert("messages".into(), json!(messages));
    if !system.is_empty() {
        out.insert("system".into(), json!(system.join("\n\n")));
    }
    for k in ["temperature", "top_p"] {
        if !req[k].is_null() {
            out.insert(k.into(), req[k].clone());
        }
    }
    match &req["stop"] {
        Value::String(s) => {
            out.insert("stop_sequences".into(), json!([s]));
        }
        Value::Array(a) => {
            out.insert("stop_sequences".into(), json!(a));
        }
        _ => {}
    }
    if let Some(tools) = req["tools"].as_array() {
        let t: Vec<Value> = tools
            .iter()
            .filter(|t| t["type"] == "function")
            .map(|t| {
                json!({
                    "name": t["function"]["name"],
                    "description": t["function"]["description"].as_str().unwrap_or(""),
                    "input_schema": if t["function"]["parameters"].is_object() { t["function"]["parameters"].clone() } else { json!({"type":"object","properties":{}}) }
                })
            })
            .collect();
        if !t.is_empty() {
            out.insert("tools".into(), json!(t));
        }
        match &req["tool_choice"] {
            Value::String(s) if s == "required" => {
                out.insert("tool_choice".into(), json!({"type": "any"}));
            }
            Value::String(s) if s == "none" => {
                out.insert("tool_choice".into(), json!({"type": "none"}));
            }
            Value::Object(o) if o.contains_key("function") => {
                out.insert("tool_choice".into(), json!({"type": "tool", "name": req["tool_choice"]["function"]["name"]}));
            }
            _ => {}
        }
    }
    if req["stream"].as_bool().unwrap_or(false) {
        out.insert("stream".into(), json!(true));
    }
    Value::Object(out)
}

fn finish_reason(stop: &str) -> &'static str {
    match stop {
        "max_tokens" => "length",
        "tool_use" => "tool_calls",
        _ => "stop",
    }
}

/// Normalize Anthropic usage. Anthropic's input_tokens exclude cached tokens; the
/// normalized `input` counts all prompt tokens.
pub fn usage_from_anthropic(u: &Value) -> Usage {
    let input = u["input_tokens"].as_u64().unwrap_or(0);
    let cr = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
    let cw = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
    Usage {
        input: input + cr + cw,
        output: u["output_tokens"].as_u64().unwrap_or(0),
        cache_read: cr,
        cache_write: cw,
        reasoning: 0,
        source: if u.is_null() { UsageSource::Unavailable } else { UsageSource::Reported },
    }
}

/// Convert an Anthropic Messages response into an OpenAI chat completion response.
pub fn response_to_openai(resp: &Value, alias: &str) -> (Value, Usage) {
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for b in resp["content"].as_array().cloned().unwrap_or_default() {
        match b["type"].as_str() {
            Some("text") => text.push_str(b["text"].as_str().unwrap_or("")),
            Some("tool_use") => tool_calls.push(json!({
                "id": b["id"],
                "type": "function",
                "function": {"name": b["name"], "arguments": serde_json::to_string(&b["input"]).unwrap_or_default()}
            })),
            _ => {}
        }
    }
    let usage = usage_from_anthropic(&resp["usage"]);
    let mut message = json!({"role": "assistant", "content": if text.is_empty() && !tool_calls.is_empty() { Value::Null } else { json!(text) }});
    if !tool_calls.is_empty() {
        message["tool_calls"] = json!(tool_calls);
    }
    let out = json!({
        "id": resp["id"].as_str().map(|s| format!("chatcmpl-{s}")).unwrap_or_else(|| "chatcmpl-llmvault".into()),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": alias,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason(resp["stop_reason"].as_str().unwrap_or("end_turn"))}],
        "usage": {
            "prompt_tokens": usage.input,
            "completion_tokens": usage.output,
            "total_tokens": usage.input + usage.output,
            "prompt_tokens_details": {"cached_tokens": usage.cache_read}
        }
    });
    (out, usage)
}

/// Incremental converter from Anthropic SSE events to OpenAI chat.completion.chunk objects.
pub struct StreamConverter {
    id: String,
    alias: String,
    created: i64,
    tool_index: std::collections::HashMap<u64, usize>,
    next_tool: usize,
    pub usage: Usage,
    pub text_len: usize,
}

impl StreamConverter {
    pub fn new(alias: &str) -> Self {
        StreamConverter {
            id: format!("chatcmpl-{}", crate::config::new_id()),
            alias: alias.to_string(),
            created: chrono::Utc::now().timestamp(),
            tool_index: Default::default(),
            next_tool: 0,
            usage: Usage { source: UsageSource::Unavailable, ..Default::default() },
            text_len: 0,
        }
    }

    fn chunk(&self, delta: Value, finish: Option<&str>) -> Value {
        json!({
            "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.alias,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        })
    }

    /// Feed one parsed Anthropic event; returns zero or more OpenAI chunks.
    pub fn feed(&mut self, ev: &Value) -> Vec<Value> {
        match ev["type"].as_str().unwrap_or("") {
            "message_start" => {
                let u = usage_from_anthropic(&ev["message"]["usage"]);
                self.usage.input = u.input;
                self.usage.cache_read = u.cache_read;
                self.usage.cache_write = u.cache_write;
                self.usage.source = UsageSource::Reported;
                vec![self.chunk(json!({"role": "assistant", "content": ""}), None)]
            }
            "content_block_start" => {
                let b = &ev["content_block"];
                if b["type"] == "tool_use" {
                    let idx = self.next_tool;
                    self.next_tool += 1;
                    self.tool_index.insert(ev["index"].as_u64().unwrap_or(0), idx);
                    vec![self.chunk(
                        json!({"tool_calls": [{"index": idx, "id": b["id"], "type": "function", "function": {"name": b["name"], "arguments": ""}}]}),
                        None,
                    )]
                } else {
                    vec![]
                }
            }
            "content_block_delta" => {
                let d = &ev["delta"];
                match d["type"].as_str() {
                    Some("text_delta") => {
                        let t = d["text"].as_str().unwrap_or("");
                        self.text_len += t.len();
                        vec![self.chunk(json!({"content": t}), None)]
                    }
                    Some("input_json_delta") => {
                        let idx = self.tool_index.get(&ev["index"].as_u64().unwrap_or(0)).copied().unwrap_or(0);
                        vec![self.chunk(json!({"tool_calls": [{"index": idx, "function": {"arguments": d["partial_json"]}}]}), None)]
                    }
                    _ => vec![],
                }
            }
            "message_delta" => {
                if let Some(o) = ev["usage"]["output_tokens"].as_u64() {
                    self.usage.output = o;
                }
                let fr = finish_reason(ev["delta"]["stop_reason"].as_str().unwrap_or("end_turn"));
                vec![self.chunk(json!({}), Some(fr))]
            }
            _ => vec![],
        }
    }

    pub fn usage_chunk(&self) -> Value {
        json!({
            "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.alias, "choices": [],
            "usage": {"prompt_tokens": self.usage.input, "completion_tokens": self.usage.output, "total_tokens": self.usage.input + self.usage.output}
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_system_tools_and_tool_results() {
        let req = json!({
            "model": "claude", "max_tokens": 100,
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "wx", "arguments": "{\"city\":\"Krakow\"}"}}]},
                {"role": "tool", "tool_call_id": "t1", "content": "sunny"}
            ],
            "tools": [{"type": "function", "function": {"name": "wx", "parameters": {"type": "object"}}}]
        });
        let out = request_from_openai(&req, "claude-sonnet");
        assert_eq!(out["system"], "be brief");
        assert_eq!(out["messages"].as_array().unwrap().len(), 3);
        assert_eq!(out["messages"][1]["content"][0]["type"], "tool_use");
        assert_eq!(out["messages"][1]["content"][0]["input"]["city"], "Krakow");
        assert_eq!(out["messages"][2]["content"][0]["type"], "tool_result");
        assert_eq!(out["tools"][0]["name"], "wx");
    }

    #[test]
    fn converts_response_and_usage() {
        let resp = json!({"id": "msg_1", "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 90}});
        let (o, u) = response_to_openai(&resp, "alias");
        assert_eq!(o["choices"][0]["message"]["content"], "hi");
        assert_eq!(u.input, 100);
        assert_eq!(u.cache_read, 90);
        assert_eq!(o["model"], "alias");
    }
}
