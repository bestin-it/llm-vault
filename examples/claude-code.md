# Claude Code through LLM Vault

LLM Vault implements the Anthropic Messages API on `/v1/messages`. Point Claude Code at the vault and
use a client token instead of an Anthropic key. The alias must be served by an **Anthropic** provider
(or by **Ollama**, which also speaks the Messages API).

```powershell
$env:ANTHROPIC_BASE_URL   = "http://127.0.0.1:8765"
$env:ANTHROPIC_AUTH_TOKEN = "lvk_..."          # client token, not an Anthropic key
$env:ANTHROPIC_MODEL      = "claude-sonnet"    # alias defined in LLM Vault
claude
```

The first request shows a consent prompt in LLM Vault (unless the client is pre-approved). Every call
is logged with tokens and cost under the client name.
