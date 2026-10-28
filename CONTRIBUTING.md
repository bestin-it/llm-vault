# Contributing to LLM Vault

Thanks for helping. Bug reports, provider presets, translations of the docs and fixes are all welcome.

## Before you start

- **Security issues** go through [SECURITY.md](SECURITY.md), never through public issues.
- For a larger change, open an issue first so we can agree on the approach.

## Development setup

```bash
# Rust stable (edition 2024). On Linux also: libfontconfig1-dev libxkbcommon-dev libwayland-dev libx11-dev
cargo run -- --demo          # isolated demo vault with synthetic data, no keys needed
cargo test                   # unit + security integration tests against a mock provider
cargo test --test live_local -- --ignored --nocapture   # optional: needs a local Ollama / llama.cpp
```

## Rules the code must keep

1. **No endpoint returns a secret.** The gateway exposes `/health`, `/v1/models`, `/v1/chat/completions`,
   `/v1/messages` and `/v1/embeddings` only. A change that adds a route needs a test in `tests/security.rs`.
2. **Configuration lives inside the encrypted KDBX file**, never in a plain settings file a client could edit.
3. **Keys never reach logs or errors.** Route every provider error through `redact.rs`.
4. **Estimates are labelled.** Usage and cost are *reported*, *estimated* or *unavailable* - never guessed silently.

## Pull requests

- Keep one topic per PR, with a short description of what changes for the user.
- `cargo test` must pass (CI runs it on Windows, macOS and Linux); run `cargo fmt` before committing.
- New provider presets: add the entry in `src/providers/mod.rs` and, if the API differs from OpenAI,
  a translation test.

By contributing you agree that your contribution is licensed under Apache-2.0.
