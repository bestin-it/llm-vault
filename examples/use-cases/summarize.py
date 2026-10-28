"""Summarise release notes with whatever engine stands behind
the alias "summarizer" in LLM Vault. The script never names an
engine or a key: the alias can point at Ollama today and at
llama.cpp, vLLM or a cloud model tomorrow.

    $env:VAULT_CLIENT_TOKEN = "lvk_..."
    python summarize.py release_notes.txt
"""
import os, sys, time

from openai import OpenAI

URL = os.environ.get("LLMVAULT_URL", "http://127.0.0.1:8765/v1")
client = OpenAI(
    base_url=URL,                             # LLM Vault, local
    api_key=os.environ["VAULT_CLIENT_TOKEN"],  # lvk_ token
    default_headers={"X-LLMVault-Agent": "summarize-script"},
)
ASK = ("Summarise these release notes in 3 bullet points, "
       "plain text, max 9 words each, lines start with '- '.")
notes = open(sys.argv[1]).read()

start = time.time()
reply = client.chat.completions.create(
    model="summarizer",              # a name, not an engine
    messages=[{"role": "system", "content": ASK},
              {"role": "user", "content": notes}],
    max_tokens=120, reasoning_effort="none",
)
print(reply.choices[0].message.content.strip())
print(f"-- alias summarizer, {time.time() - start:.1f} s")
