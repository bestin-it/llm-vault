"""Overnight ticket bot: triage support tickets with a local
model through LLM Vault. No provider API key anywhere - the
script only gets a scoped LLM Vault token (one model,
pre-approved, daily budget); Ollama runs the model here.

    pip install openai
    $env:VAULT_CLIENT_TOKEN = "lvk_..."
    python ticket_bot.py tickets.csv
"""
import csv, json, os, sys, time

from openai import OpenAI

URL = os.environ.get("LLMVAULT_URL", "http://127.0.0.1:8765/v1")
client = OpenAI(
    base_url=URL,                             # LLM Vault, local
    api_key=os.environ["VAULT_CLIENT_TOKEN"],  # lvk_ token
    default_headers={"X-LLMVault-Agent": "ticket-bot"},
)
PROMPT = ("Triage this support ticket. Reply with JSON only: "
          "category (billing, bug, outage, feature, account, "
          "api, privacy, sales), priority (low, medium, high), "
          "summary (max 6 words).")

start = time.time()
tickets = list(csv.DictReader(open(sys.argv[1])))
out = csv.writer(open("triage.csv", "w", newline=""))
n = len(tickets)
for i, t in enumerate(tickets, 1):
    reply = client.chat.completions.create(
        model="qwen-local",                   # one alias
        messages=[{"role": "system", "content": PROMPT},
                  {"role": "user", "content": t["text"]}],
        response_format={"type": "json_object"},
        max_tokens=80, reasoning_effort="none",
    )
    r = json.loads(reply.choices[0].message.content)
    out.writerow([t["id"], r["category"], r["priority"],
                  r["summary"]])
    print(f"[{i:02d}/{n}] #{t['id']}  {r['priority']:<6} "
          f"{r['category']:<8} {r['summary']}")
took = time.time() - start
print(f"done: {n} tickets in {took:.1f} s, API keys: 0")
