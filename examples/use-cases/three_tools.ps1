# One machine, three AI tools, three LLM Vault tokens - one audit log.
# Each tool gets its own token, so the vault knows who spent what.
#   $env:TOKEN_SCRIPT / $env:TOKEN_CLAUDE / $env:TOKEN_CURL = "lvk_..."
$vault = "http://127.0.0.1:8765/v1"

# 1. a Python script (OpenAI SDK)
$env:VAULT_CLIENT_TOKEN = $env:TOKEN_SCRIPT
python summarize.py release_notes.txt

# 2. Claude Code on a local model
$env:VAULT_CLIENT_TOKEN = $env:TOKEN_CLAUDE
python claude_local.py "Name the main file of this repo."

# 3. a quick curl call
curl.exe -s "$vault/chat/completions" `
  -H "Authorization: Bearer $env:TOKEN_CURL" `
  -d '{"model":"qwen3-0.6b","messages":[{"role":"user","content":"hi"}]}'
