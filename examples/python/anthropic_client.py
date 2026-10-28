"""Anthropic SDK (Messages API) through LLM Vault - works for aliases served by an Anthropic
or Ollama provider.

    pip install anthropic
"""
import os

import anthropic

client = anthropic.Anthropic(
    base_url=os.environ.get("LLMVAULT_ROOT", "http://127.0.0.1:8765"),  # no /v1 here
    api_key=os.environ["VAULT_CLIENT_TOKEN"],
)
msg = client.messages.create(
    model=os.environ.get("LLMVAULT_MODEL", "claude-sonnet"),
    max_tokens=300,
    messages=[{"role": "user", "content": "Explain in two sentences why agents should not hold API keys."}],
)
print(msg.content[0].text)
