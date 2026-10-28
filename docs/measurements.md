# Measurements (2026-10-21)

Machine: Windows 11 Pro for Workstations, AMD Radeon PRO W7900 workstation. Build: debug test profile
(dependencies at opt-level 2). Single runs - treat as indicative, not as a benchmark.

## Live end-to-end tests (`cargo test --test live_local -- --ignored --nocapture`)

| Backend | Model | Direct call | Through LLM Vault | Gateway overhead | Streaming through vault |
|---|---|---|---|---|---|
| Ollama 0.x (local) | qwen3:0.6b | 1,087 ms (200 tok) | 1,094 ms, 44 in / 200 out, usage *reported* | ~7 ms | 199 SSE chunks, `[DONE]` |
| llama.cpp `llama-server` b11782 | Qwen3.5-2B Q4_K_M (GGUF from the LM Studio model folder) | 39,846 ms (1,200 tok) | 39,888 ms, 44 in / 1,200 out, *reported* | ~42 ms | 1,202 SSE chunks |

* `/v1/messages` (Anthropic format, used by Claude Code) through Ollama: HTTP 200, usage reported
  (`input_tokens` 10, `cache_read_input_tokens` 3).
* qwen3 answered the decision prompt ("HTTP 429 - retry immediately, with backoff, or give up?") with
  **"retry with backoff"**.
* Second Ollama run showed the gateway call *faster* than the direct call (-495 ms) - model-side
  variance dominates; the gateway adds single-digit to low-double-digit milliseconds.

## Security test suite (`cargo test`)

* 12 unit tests + 13 integration tests (mock provider): all green.
* Covered: no endpoint returns a secret (24 probes), 401/403/404/423/429 paths, consent deny / once /
  session / timeout, revocation, lock, key redaction in client errors and in the audit database,
  encrypted vault file, OpenAI -> Anthropic translation, budgets and rate limits.

## KeePass compatibility

Vault created by LLM Vault opened with an independent implementation (pykeepass):
`KDBX 4.1`, cipher `AES-256`, KDF `Argon2id` (64 MiB, 5 iterations, parallelism 4); groups and entries
readable; wrong password -> `CredentialsError`.

* Streaming **tool calls** through the gateway (VS Code Copilot agent-mode shape): qwen3:0.6b called `read_file` - verified.

## Vault timing (release build, `cargo test --release --test kdf_timing -- --ignored --nocapture`)

Argon2id 64 MiB, 5 iterations, parallelism 4:
create 319 ms · save with 200 entries 340 ms · unlock x5: 360 / 335 / 325 / 326 / 340 ms ·
wrong password rejected after 313 ms · file size 11,969 bytes for 200 entries.
Every change re-encrypts the file with a fresh KDF run: 200 sequential edits took ~70 s in total.

## Build artefacts (Windows x64, release)

llmvault.exe 36.4 MB · llmvault-server.exe 11.6 MB · installer 13.0 MB (Inno Setup, LZMA2) ·
portable ZIP 19.4 MB. Per-user install without admin rights; silent install + uninstall verified.
