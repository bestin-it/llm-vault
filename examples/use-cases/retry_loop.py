"""A buggy retry loop: on any error it asks again at once,
forever. LLM Vault's per-token limits stop it: the token allows
20 requests per minute and a small daily budget, so after 20
calls the gateway answers HTTP 429 and the loop only bounces off
the vault - no provider is called, nothing is billed.
(For the demo the loop gives up after MAX_ATTEMPTS.)

    $env:VAULT_CLIENT_TOKEN = "lvk_..."
    python retry_loop.py
"""
import os

from openai import APIStatusError, OpenAI

URL = os.environ.get("LLMVAULT_URL", "http://127.0.0.1:8765/v1")
client = OpenAI(
    base_url=URL,
    api_key=os.environ["VAULT_CLIENT_TOKEN"],
    default_headers={"X-LLMVault-Agent": "nightly-sync"},
    max_retries=0,
)
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "32"))

for attempt in range(1, MAX_ATTEMPTS + 1):    # BUG: no limit
    try:
        client.chat.completions.create(
            model="qwen3-0.6b", max_tokens=4,
            messages=[{"role": "user", "content": "ping"}])
        print(f"attempt {attempt:02d}  200 OK")
    except APIStatusError as e:                # BUG: no backoff
        body = e.body if isinstance(e.body, dict) else {}
        err = body.get("error", {})
        code = body.get("code") or err.get("code", "")
        print(f"attempt {attempt:02d}  {e.status_code} {code}"
              "  (provider not called)")
