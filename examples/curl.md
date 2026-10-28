# curl

```bash
TOKEN=lvk_...   # client token from LLM Vault > Clients & agents
curl http://127.0.0.1:8765/v1/models -H "Authorization: Bearer $TOKEN"

curl http://127.0.0.1:8765/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "X-LLMVault-Agent: curl" \
  -d '{"model": "qwen-local", "messages": [{"role": "user", "content": "Hello"}]}'
```

Typical refusals (JSON body `{"error": {"type": ..., "message": ...}}`):

| HTTP | type | meaning |
|---|---|---|
| 401 | `missing_token` / `invalid_token` / `token_revoked` / `token_expired` | the client token is not valid |
| 403 | `model_not_allowed` / `consent_denied` / `consent_timeout` | policy or the vault owner said no |
| 404 | `model_not_found` | unknown alias |
| 423 | `vault_locked` | the vault is locked - ask the owner to unlock it |
| 429 | `rate_limited` / `budget_exceeded` | per-client limits |
