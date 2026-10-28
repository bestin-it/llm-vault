"""Call any model configured in LLM Vault with the official OpenAI SDK.

The script only knows a short-lived *client token* (VAULT_CLIENT_TOKEN). The provider key
(Azure AI Foundry, OpenAI, Ollama Cloud, ...) never leaves the vault.

    pip install openai
    set VAULT_CLIENT_TOKEN=lvk_...        (PowerShell: $env:VAULT_CLIENT_TOKEN="lvk_...")
    python openai_client.py
"""
import os

from openai import OpenAI

client = OpenAI(
    base_url=os.environ.get("LLMVAULT_URL", "http://127.0.0.1:8765/v1"),
    api_key=os.environ["VAULT_CLIENT_TOKEN"],
    # Optional labels that show up in the vault's activity log and cost reports.
    default_headers={"X-LLMVault-Agent": "python-example", "X-LLMVault-Project": "demo"},
)

print("Models this token may use:", [m.id for m in client.models.list().data])

reply = client.chat.completions.create(
    model=os.environ.get("LLMVAULT_MODEL", "foundry-glm"),
    messages=[{"role": "user", "content": "Review this function: def add(a, b): return a - b"}],
)
print(reply.choices[0].message.content)

# Streaming works the same way
stream = client.chat.completions.create(
    model=os.environ.get("LLMVAULT_MODEL", "foundry-glm"),
    messages=[{"role": "user", "content": "Write a haiku about API keys that stay home."}],
    stream=True,
)
for chunk in stream:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
print()
