"""Play attacker with a leaked LLM Vault token.
  1. ask the gateway for the provider keys  -> 404
  2. use a model the token was never given  -> 403
  3. after the owner presses Revoke          -> 401

    $env:VAULT_CLIENT_TOKEN = "lvk_..."   # the leaked one
    python leaked_token.py [seconds to wait for the owner]
"""
import json, os, sys, time, urllib.error, urllib.request

URL = os.environ.get("LLMVAULT_URL", "http://127.0.0.1:8765/v1")
TOKEN = os.environ["VAULT_CLIENT_TOKEN"]


def call(method, path, model=None):
    body = {"model": model, "max_tokens": 4,
            "messages": [{"role": "user", "content": "hi"}]}
    req = urllib.request.Request(
        URL + path, method=method,
        data=json.dumps(body).encode() if model else None,
        headers={"Authorization": f"Bearer {TOKEN}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return f"{r.status} OK"
    except urllib.error.HTTPError as e:
        err = json.loads(e.read() or b"{}").get("error", {})
        return f"{e.code} {err.get('code', '')}"


print(f"leaked token: {TOKEN[:10]}...")
print("1. GET  /secrets        ->", call("GET", "/secrets"))
print("2. POST gpt-5-mini      ->",
      call("POST", "/chat/completions", "foundry-gpt5-mini"))
print("   ...the owner opens LLM Vault and presses Revoke", flush=True)
time.sleep(float(sys.argv[1]) if len(sys.argv) > 1 else 4.0)
print("3. POST qwen3-0.6b      ->",
      call("POST", "/chat/completions", "qwen3-0.6b"))
