# Changelog

## 0.1.0 - 2026-10-26

First public release.

- KeePass-compatible password manager: KDBX 4.1, AES-256, Argon2id (64 MiB), ChaCha20-protected fields,
  groups, logins, notes, password generator, clipboard auto-clear, import of existing KeePass databases.
- Profiles with their own login password (Argon2id), independent of the vault master password.
- Built-in LLM gateway on `127.0.0.1:8765`: OpenAI `/v1/chat/completions` (streaming, tool calls),
  Anthropic `/v1/messages` (Claude Code), `/v1/embeddings`, `/v1/models`. No endpoint returns a secret.
- 38 provider integrations, local server discovery (Ollama, LM Studio, llama.cpp, vLLM).
- Client tokens with model allow-lists, expiry, rate limits, daily / monthly budgets and instant revocation.
- Consent prompts (once / per session / standing rule) with an anti-click-jacking arming delay.
- Audit log and analytics: tokens, cost, latency, CSV / JSON export.
- `llmvault-server`: headless gateway for the strong-isolation mode.
- VS Code GitHub Copilot Chat snippet (Custom Endpoint) with every model of the token.
- `--demo` mode with synthetic data.
