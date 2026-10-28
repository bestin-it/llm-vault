# Use cases - the scripts from the video series

Every script here ran for real in the "LLM Vault in practice" videos, through the gateway, on local models.
None of them contains a provider key: each one reads a scoped LLM Vault token from `VAULT_CLIENT_TOKEN`
(and the gateway URL from `LLMVAULT_URL`, default `http://127.0.0.1:8765/v1`).

| Script | What it shows | Episode |
|---|---|---|
| [`ticket_bot.py`](ticket_bot.py) + `tickets.csv` | an overnight support-ticket triage bot on a local Qwen3 model, writes `triage.csv` | E1 · A Python script that runs AI all night - with no API key |
| [`summarize.py`](summarize.py) + `release_notes.txt` | the script asks for an alias (`summarizer`); you switch the engine behind it (Ollama → llama.cpp) in the vault | E2 · Ollama → llama.cpp without changing a line of code |
| [`retry_loop.py`](retry_loop.py) | a buggy retry loop with no backoff hits the token's rate limit: HTTP 429, the provider is never called | E3 · An infinite retry loop vs. an AI API bill |
| [`claude_local.py`](claude_local.py) | starts Claude Code against `/v1/messages` with a vault token - a local model, no Anthropic key | E4 · Claude Code on a local model |
| [`leaked_token.py`](leaked_token.py) | plays attacker with a leaked token: 404 for keys, 403 for other models, 401 after Revoke | E5 · I leaked my AI agent's token on purpose |
| [`three_tools.ps1`](three_tools.ps1) | a Python script, Claude Code and curl, each with its own token, in one audit log | E6 · One audit log for every AI tool on your machine |

Setup for each episode (provider, model alias, token limits) and the videos: <https://bestin-it.com/llm-vault/>.

```powershell
pip install openai
$env:VAULT_CLIENT_TOKEN = "lvk_..."      # from LLM Vault → Clients & agents → New client token
python ticket_bot.py tickets.csv
```
