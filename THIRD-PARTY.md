# Third-party software

LLM Vault is licensed under Apache-2.0. It is built on these open-source components (main ones;
the full list with versions is in `Cargo.lock`):

| Component | Purpose | License |
|---|---|---|
| Slint | native UI toolkit | Royalty-free Desktop, Mobile and Web Applications License v2.0 (with attribution "Made with Slint" in the About page) / GPLv3 |
| keepass-rs (`keepass`) | KDBX 4 read / write | MIT |
| rust-argon2, aes, chacha20, sha2, hmac (RustCrypto) | cryptography | MIT / Apache-2.0 |
| tokio, axum, hyper, tower | async runtime and HTTP gateway | MIT |
| reqwest, rustls | outbound HTTPS to providers | MIT / Apache-2.0 / ISC |
| rusqlite + SQLite | audit database | MIT / public domain |
| serde, serde_json, chrono, uuid, regex | utilities | MIT / Apache-2.0 |
| arboard | clipboard with auto-clear | MIT / Apache-2.0 |
| rfd | native file dialogs | MIT |
| zeroize, subtle | secret hygiene, constant-time compare | MIT / Apache-2.0 |
