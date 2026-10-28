//! Provider catalog ("integrations") and upstream request building.

pub mod anthropic;

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::{AuthStyle, ProviderConfig, ProviderKind, VaultConfig};

/// A ready-made integration shown in the "Add provider" catalog.
#[derive(Debug, Clone)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: ProviderKind,
    pub base_url: &'static str,
    pub auth: AuthStyle,
    pub needs_key: bool,
    pub category: &'static str,
    pub key_url: &'static str,
    pub description: &'static str,
    pub example_models: &'static [&'static str],
}

pub const CATALOG: &[Preset] = &[
    Preset {
        id: "ollama-local",
        name: "Ollama (local)",
        kind: ProviderKind::Ollama,
        base_url: "http://127.0.0.1:11434",
        auth: AuthStyle::None,
        needs_key: false,
        category: "Local",
        key_url: "https://ollama.com/download",
        description: "Models running on this machine through the Ollama daemon. No key, no per-token cost.",
        example_models: &["qwen3:8b", "llama3.2", "gpt-oss:20b"],
    },
    Preset {
        id: "ollama-cloud",
        name: "Ollama Cloud (ollama.com)",
        kind: ProviderKind::Ollama,
        base_url: "https://ollama.com",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://ollama.com/settings/keys",
        description: "Large open models hosted by ollama.com. Create an API key in your ollama.com account settings.",
        example_models: &["gpt-oss:120b", "qwen3-coder:480b", "deepseek-v3.1:671b"],
    },
    Preset {
        id: "openai",
        name: "OpenAI",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.openai.com/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://platform.openai.com/api-keys",
        description: "GPT models through the OpenAI platform API.",
        example_models: &["gpt-5", "gpt-5-mini", "gpt-4.1"],
    },
    Preset {
        id: "azure-foundry",
        name: "Azure AI Foundry",
        kind: ProviderKind::OpenAi,
        base_url: "https://<resource>.services.ai.azure.com/openai/v1",
        auth: AuthStyle::ApiKeyHeader,
        needs_key: true,
        category: "Enterprise",
        key_url: "https://ai.azure.com",
        description: "Foundry models (GPT, GLM, DeepSeek, Llama, Mistral...) via the OpenAI v1-compatible endpoint. Replace <resource>.",
        example_models: &["gpt-5-mini", "DeepSeek-V3.1", "glm-4.6"],
    },
    Preset {
        id: "azure-openai",
        name: "Azure OpenAI (deployments)",
        kind: ProviderKind::AzureOpenAi,
        base_url: "https://<resource>.openai.azure.com",
        auth: AuthStyle::ApiKeyHeader,
        needs_key: true,
        category: "Enterprise",
        key_url: "https://portal.azure.com",
        description: "Classic Azure OpenAI deployment URLs with api-version. Use the deployment name as the upstream model.",
        example_models: &["my-gpt-deployment"],
    },
    Preset {
        id: "anthropic",
        name: "Anthropic (Claude)",
        kind: ProviderKind::Anthropic,
        base_url: "https://api.anthropic.com",
        auth: AuthStyle::XApiKey,
        needs_key: true,
        category: "Cloud",
        key_url: "https://console.anthropic.com/settings/keys",
        description: "Claude models. Works with OpenAI-style clients (translated) and natively on /v1/messages.",
        example_models: &["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
    },
    Preset {
        id: "gemini",
        name: "Google Gemini",
        kind: ProviderKind::OpenAi,
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://aistudio.google.com/apikey",
        description: "Gemini models through Google's OpenAI-compatible endpoint.",
        example_models: &["gemini-2.5-pro", "gemini-2.5-flash"],
    },
    Preset {
        id: "openrouter",
        name: "OpenRouter",
        kind: ProviderKind::OpenAi,
        base_url: "https://openrouter.ai/api/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Router",
        key_url: "https://openrouter.ai/keys",
        description: "One key for hundreds of models from many vendors.",
        example_models: &["openai/gpt-5", "anthropic/claude-sonnet-4.5", "qwen/qwen3-coder"],
    },
    Preset {
        id: "groq",
        name: "Groq",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.groq.com/openai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://console.groq.com/keys",
        description: "Very fast inference for open models on LPUs.",
        example_models: &["llama-3.3-70b-versatile", "openai/gpt-oss-120b"],
    },
    Preset {
        id: "mistral",
        name: "Mistral AI",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.mistral.ai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://console.mistral.ai/api-keys",
        description: "Mistral and Codestral models (EU hosted).",
        example_models: &["mistral-large-latest", "codestral-latest"],
    },
    Preset {
        id: "deepseek",
        name: "DeepSeek",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.deepseek.com/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://platform.deepseek.com/api_keys",
        description: "DeepSeek chat and reasoning models.",
        example_models: &["deepseek-chat", "deepseek-reasoner"],
    },
    Preset {
        id: "xai",
        name: "xAI (Grok)",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.x.ai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://console.x.ai",
        description: "Grok models.",
        example_models: &["grok-4", "grok-code-fast-1"],
    },
    Preset {
        id: "together",
        name: "Together AI",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.together.xyz/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://api.together.ai/settings/api-keys",
        description: "Open models (Llama, Qwen, DeepSeek...) as a service.",
        example_models: &["meta-llama/Llama-3.3-70B-Instruct-Turbo"],
    },
    Preset {
        id: "fireworks",
        name: "Fireworks AI",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.fireworks.ai/inference/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://fireworks.ai/account/api-keys",
        description: "Fast serverless open models.",
        example_models: &["accounts/fireworks/models/qwen3-coder-480b-a35b-instruct"],
    },
    Preset {
        id: "cerebras",
        name: "Cerebras",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.cerebras.ai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://cloud.cerebras.ai",
        description: "Wafer-scale inference for open models.",
        example_models: &["gpt-oss-120b", "qwen-3-coder-480b"],
    },
    Preset {
        id: "perplexity",
        name: "Perplexity",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.perplexity.ai",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://www.perplexity.ai/settings/api",
        description: "Sonar models with built-in web search.",
        example_models: &["sonar", "sonar-pro"],
    },
    Preset {
        id: "huggingface",
        name: "Hugging Face Inference",
        kind: ProviderKind::OpenAi,
        base_url: "https://router.huggingface.co/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Router",
        key_url: "https://huggingface.co/settings/tokens",
        description: "Inference Providers router for models hosted on the Hub.",
        example_models: &["openai/gpt-oss-120b", "Qwen/Qwen3-Coder-480B-A35B-Instruct"],
    },
    Preset {
        id: "lmstudio",
        name: "LM Studio (local)",
        kind: ProviderKind::OpenAi,
        base_url: "http://127.0.0.1:1234/v1",
        auth: AuthStyle::None,
        needs_key: false,
        category: "Local",
        key_url: "https://lmstudio.ai",
        description: "Models served by LM Studio's local server (Developer tab > Start server, or `lms server start`).",
        example_models: &["qwen/qwen3-8b"],
    },
    Preset {
        id: "llama-cpp",
        name: "llama.cpp server (local)",
        kind: ProviderKind::OpenAi,
        base_url: "http://127.0.0.1:8080/v1",
        auth: AuthStyle::Bearer,
        needs_key: false,
        category: "Local",
        key_url: "https://github.com/ggml-org/llama.cpp/tree/master/tools/server",
        description: "llama-server from llama.cpp (GGUF models). Set a key only if you started it with --api-key.",
        example_models: &["qwen3-8b-q4_k_m.gguf"],
    },
    Preset {
        id: "vllm",
        name: "vLLM (local / LAN)",
        kind: ProviderKind::OpenAi,
        base_url: "http://127.0.0.1:8000/v1",
        auth: AuthStyle::Bearer,
        needs_key: false,
        category: "Local",
        key_url: "https://docs.vllm.ai",
        description: "High-throughput OpenAI-compatible server. Use 'Allow HTTP' for a LAN GPU box.",
        example_models: &["Qwen/Qwen3-8B"],
    },
    Preset {
        id: "cohere",
        name: "Cohere",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.cohere.ai/compatibility/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://dashboard.cohere.com/api-keys",
        description: "Command models through Cohere's OpenAI compatibility API.",
        example_models: &["command-a-03-2025"],
    },
    Preset {
        id: "zai",
        name: "Z.ai (GLM)",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.z.ai/api/paas/v4",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://z.ai/manage-apikey/apikey-list",
        description: "GLM models from Z.ai (Zhipu).",
        example_models: &["glm-4.6", "glm-4.5-air"],
    },
    Preset {
        id: "zai-coding",
        name: "Z.ai GLM Coding Plan",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.z.ai/api/coding/paas/v4",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Coding plan",
        key_url: "https://z.ai/subscribe",
        description: "GLM Coding Plan subscription endpoint for coding agents.",
        example_models: &["glm-4.6"],
    },
    Preset {
        id: "bailian",
        name: "Alibaba Cloud Model Studio (Qwen)",
        kind: ProviderKind::OpenAi,
        base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://bailian.console.alibabacloud.com",
        description: "Qwen models via DashScope compatible mode (use dashscope.aliyuncs.com for mainland China).",
        example_models: &["qwen-plus", "qwen3-coder-plus"],
    },
    Preset {
        id: "minimax",
        name: "MiniMax",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.minimax.io/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://platform.minimax.io",
        description: "MiniMax text models (use api.minimaxi.com for mainland China).",
        example_models: &["MiniMax-M2"],
    },
    Preset {
        id: "xiaomi-mimo",
        name: "Xiaomi MiMo",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.xiaomimimo.com/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://platform.xiaomimimo.com",
        description: "Xiaomi MiMo models (verify the base URL in your console).",
        example_models: &["mimo-v2-flash"],
    },
    Preset {
        id: "chutes",
        name: "Chutes AI",
        kind: ProviderKind::OpenAi,
        base_url: "https://llm.chutes.ai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://chutes.ai",
        description: "Decentralized serverless inference for open models.",
        example_models: &["deepseek-ai/DeepSeek-V3.1"],
    },
    Preset {
        id: "kilo",
        name: "Kilo AI Gateway",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.kilo.ai/api/gateway",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Router",
        key_url: "https://kilo.ai",
        description: "Kilo Code gateway (OpenAI-compatible).",
        example_models: &["anthropic/claude-sonnet-4.5"],
    },
    Preset {
        id: "edenai",
        name: "Eden AI",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.edenai.run/v3",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Router",
        key_url: "https://app.edenai.run",
        description: "Multi-vendor AI router.",
        example_models: &["openai/gpt-4o-mini"],
    },
    Preset {
        id: "kimi-code",
        name: "Kimi Code (Moonshot)",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.kimi.com/coding/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Coding plan",
        key_url: "https://www.kimi.com",
        description: "Kimi coding plan endpoint (subscription, no per-token price).",
        example_models: &["kimi-for-coding"],
    },
    Preset {
        id: "moonshot",
        name: "Moonshot AI (Kimi API)",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.moonshot.ai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://platform.moonshot.ai",
        description: "Kimi K2 models on the Moonshot platform.",
        example_models: &["kimi-k2-0905-preview"],
    },
    Preset {
        id: "opencode-zen",
        name: "OpenCode Zen",
        kind: ProviderKind::OpenAi,
        base_url: "https://opencode.ai/zen/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Coding plan",
        key_url: "https://opencode.ai/zen",
        description: "Curated coding models from OpenCode (OpenAI-compatible models).",
        example_models: &["qwen3-coder"],
    },
    Preset {
        id: "oracle-genai",
        name: "Oracle OCI Generative AI",
        kind: ProviderKind::OpenAi,
        base_url: "https://inference.generativeai.us-chicago-1.oci.oraclecloud.com/20231130/actions/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Enterprise",
        key_url: "https://cloud.oracle.com",
        description: "OCI Generative AI OpenAI-compatible endpoint (region specific, API key with IAM policy).",
        example_models: &["openai.gpt-oss-120b"],
    },
    Preset {
        id: "bedrock-openai",
        name: "Amazon Bedrock (OpenAI-compatible)",
        kind: ProviderKind::OpenAi,
        base_url: "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Enterprise",
        key_url: "https://console.aws.amazon.com/bedrock",
        description: "Bedrock Chat Completions endpoint with a Bedrock API key (bearer). SigV4 is planned.",
        example_models: &["openai.gpt-oss-120b-1:0"],
    },
    Preset {
        id: "meta-llama",
        name: "Meta Llama API",
        kind: ProviderKind::OpenAi,
        base_url: "https://api.llama.com/compat/v1",
        auth: AuthStyle::Bearer,
        needs_key: true,
        category: "Cloud",
        key_url: "https://llama.developer.meta.com",
        description: "Meta's Llama API, OpenAI-compatible endpoint.",
        example_models: &["Llama-4-Maverick-17B-128E-Instruct-FP8"],
    },
    Preset {
        id: "sglang",
        name: "SGLang (local / LAN)",
        kind: ProviderKind::OpenAi,
        base_url: "http://127.0.0.1:30000/v1",
        auth: AuthStyle::Bearer,
        needs_key: false,
        category: "Local",
        key_url: "https://docs.sglang.ai",
        description: "SGLang OpenAI-compatible server. Key only if started with --api-key.",
        example_models: &["Qwen/Qwen3-8B"],
    },
    Preset {
        id: "llm-d",
        name: "llm-d (Kubernetes)",
        kind: ProviderKind::OpenAi,
        base_url: "https://llm-d.example.internal/v1",
        auth: AuthStyle::Bearer,
        needs_key: false,
        category: "Enterprise",
        key_url: "https://llm-d.ai",
        description: "llm-d inference router / EPP service in your cluster.",
        example_models: &["meta-llama/Llama-3.1-8B-Instruct"],
    },
    Preset {
        id: "openai-compatible",
        name: "Custom OpenAI-compatible (SGLang, TGI, LocalAI...)",
        kind: ProviderKind::OpenAi,
        base_url: "http://127.0.0.1:8000/v1",
        auth: AuthStyle::Bearer,
        needs_key: false,
        category: "Local",
        key_url: "https://docs.vllm.ai",
        description: "Any server that implements /v1/chat/completions. Key is optional.",
        example_models: &["Qwen/Qwen3-8B"],
    },
];

pub fn preset(id: &str) -> Option<&'static Preset> {
    CATALOG.iter().find(|p| p.id == id)
}

/// Fill a fresh configuration with sensible defaults (no providers are added automatically).
pub fn seed_default_config(_cfg: &mut VaultConfig) {}

/// Everything needed to perform one upstream call. Holds the secret only for the duration
/// of the call; it is zeroized when dropped.
pub struct Upstream {
    pub kind: ProviderKind,
    pub base_url: String,
    pub auth: AuthStyle,
    pub api_version: Option<String>,
    pub secret: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream").field("kind", &self.kind).field("base_url", &self.base_url).field("secret", &"[redacted]").finish()
    }
}

impl Upstream {
    pub fn from_config(p: &ProviderConfig, secret: Option<Zeroizing<String>>) -> Self {
        Upstream { kind: p.kind, base_url: p.base_url.trim_end_matches('/').to_string(), auth: p.auth, api_version: p.api_version.clone(), secret }
    }

    fn ollama_host(&self) -> String {
        self.base_url.trim_end_matches("/v1").trim_end_matches("/api").to_string()
    }

    pub fn chat_url(&self, upstream_model: &str) -> String {
        match self.kind {
            ProviderKind::OpenAi => format!("{}/chat/completions", self.base_url),
            ProviderKind::Ollama => format!("{}/v1/chat/completions", self.ollama_host()),
            ProviderKind::AzureOpenAi => format!(
                "{}/openai/deployments/{}/chat/completions?api-version={}",
                self.base_url,
                upstream_model,
                self.api_version.as_deref().unwrap_or("2024-10-21")
            ),
            ProviderKind::Anthropic => format!("{}/v1/messages", self.base_url),
        }
    }

    pub fn messages_url(&self) -> Option<String> {
        match self.kind {
            ProviderKind::Anthropic => Some(format!("{}/v1/messages", self.base_url)),
            // Ollama implements the Anthropic Messages API on /v1/messages.
            ProviderKind::Ollama => Some(format!("{}/v1/messages", self.ollama_host())),
            _ => None,
        }
    }

    pub fn embeddings_url(&self, upstream_model: &str) -> Option<String> {
        match self.kind {
            ProviderKind::OpenAi => Some(format!("{}/embeddings", self.base_url)),
            ProviderKind::Ollama => Some(format!("{}/v1/embeddings", self.ollama_host())),
            ProviderKind::AzureOpenAi => Some(format!(
                "{}/openai/deployments/{}/embeddings?api-version={}",
                self.base_url,
                upstream_model,
                self.api_version.as_deref().unwrap_or("2024-10-21")
            )),
            ProviderKind::Anthropic => None,
        }
    }

    pub fn models_url(&self) -> Option<String> {
        match self.kind {
            ProviderKind::OpenAi => Some(format!("{}/models", self.base_url)),
            ProviderKind::Ollama => Some(format!("{}/api/tags", self.ollama_host())),
            ProviderKind::Anthropic => Some(format!("{}/v1/models?limit=100", self.base_url)),
            ProviderKind::AzureOpenAi => None,
        }
    }

    /// Attach authentication headers. This is the only place where a provider key leaves
    /// the vault - inside the outbound TLS request to the configured provider host.
    pub fn authorize(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let rb = if self.kind == ProviderKind::Anthropic { rb.header("anthropic-version", "2023-06-01") } else { rb };
        match (&self.secret, self.auth) {
            (Some(s), AuthStyle::Bearer) => rb.bearer_auth(s.as_str()),
            (Some(s), AuthStyle::ApiKeyHeader) => rb.header("api-key", s.as_str()),
            (Some(s), AuthStyle::XApiKey) => rb.header("x-api-key", s.as_str()),
            _ => rb,
        }
    }
}

/// Egress policy: provider URLs must be HTTPS, except loopback hosts or explicit opt-in.
pub fn check_egress(p: &ProviderConfig) -> Result<()> {
    let url = reqwest::Url::parse(&p.base_url).map_err(|_| anyhow!("invalid base URL"))?;
    if url.host_str().map(|h| h.contains('<')).unwrap_or(true) {
        bail!("base URL still contains a placeholder");
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = url.host_str().unwrap_or("");
            let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
            if loopback || p.allow_http {
                Ok(())
            } else {
                bail!("plain HTTP is only allowed for localhost (enable 'Allow HTTP' for LAN servers)")
            }
        }
        s => bail!("unsupported URL scheme '{s}'"),
    }
}

/// Shared HTTP client: no redirects (a redirect could forward the key to another host),
/// rustls, sane timeouts.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(300))
        .user_agent(concat!("LLM-Vault/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("http client")
}

/// List model ids offered by a provider (for the "Discover models" button).
pub async fn discover_models(client: &reqwest::Client, up: &Upstream) -> Result<Vec<String>> {
    let Some(url) = up.models_url() else {
        bail!("this provider type does not support model listing - type the deployment name instead");
    };
    let resp = up.authorize(client.get(&url)).timeout(Duration::from_secs(20)).send().await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!("provider returned HTTP {}", status.as_u16());
    }
    let mut ids: Vec<String> = match up.kind {
        ProviderKind::Ollama => body["models"]
            .as_array()
            .map(|a| a.iter().filter_map(|m| m["name"].as_str().or(m["model"].as_str()).map(String::from)).collect())
            .unwrap_or_default(),
        _ => body["data"].as_array().map(|a| a.iter().filter_map(|m| m["id"].as_str().map(String::from)).collect()).unwrap_or_default(),
    };
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Lightweight connectivity + credential check.
pub async fn test_connection(client: &reqwest::Client, up: &Upstream) -> Result<String> {
    match up.models_url() {
        Some(_) => {
            let ids = discover_models(client, up).await?;
            Ok(format!("Connected - {} model(s) available", ids.len()))
        }
        None => {
            let url = format!("{}/openai/models?api-version={}", up.base_url, up.api_version.as_deref().unwrap_or("2024-10-21"));
            let resp = up.authorize(client.get(&url)).timeout(Duration::from_secs(20)).send().await?;
            if resp.status().is_success() { Ok("Connected".into()) } else { bail!("provider returned HTTP {}", resp.status().as_u16()) }
        }
    }
}
