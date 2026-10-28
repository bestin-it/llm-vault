"""Claude Code on a local model through LLM Vault - no
Anthropic key on this machine. LLM Vault speaks the Anthropic
Messages API (/v1/messages) and translates every call for the
provider behind the alias - here Ollama on this workstation.

    $env:VAULT_CLIENT_TOKEN = "lvk_..."
    python claude_local.py "What does this repo do?"
"""
import os, subprocess, sys

URL = os.environ.get("LLMVAULT_URL", "http://127.0.0.1:8765/v1")
env = dict(os.environ,
    ANTHROPIC_BASE_URL=URL.removesuffix("/v1"),   # LLM Vault
    ANTHROPIC_AUTH_TOKEN=os.environ["VAULT_CLIENT_TOKEN"],
    ANTHROPIC_MODEL="qwen-local",                 # Ollama
    ANTHROPIC_SMALL_FAST_MODEL="qwen-local",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
)
env.pop("ANTHROPIC_API_KEY", None)                # none here

ask = sys.argv[1]
print(f'$ claude -p "{ask}"', flush=True)
claude = "claude.cmd" if os.name == "nt" else "claude"
run = subprocess.run([claude, "-p", ask], env=env,
                     stdin=subprocess.DEVNULL,
                     cwd=os.environ.get("REPO_DIR", "."))
sys.exit(run.returncode)
