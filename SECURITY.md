# Security policy

LLM Vault guards passwords and LLM provider keys, so security reports get priority over everything else.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Report it privately through
[GitHub Security Advisories](https://github.com/bestin-it/llm-vault/security/advisories/new).

Include the version (`llmvault --version`), the OS, the steps to reproduce and what an attacker gains.
You will get an answer within 7 days. Fixes ship in a new release on
[bestin-it.com/llm-vault](https://bestin-it.com/llm-vault/), and the advisory credits you unless you
prefer otherwise.

## In scope

- Any way for a gateway client (token holder, AI agent, web page) to read a provider key, a password,
  the configuration or another client's data.
- Bypassing a model allow-list, consent, budget, rate limit, expiry, revocation or the vault lock.
- Keys or passwords reaching logs, the audit database, error messages or the clipboard history.
- Weaknesses in the KDBX 4 handling (encryption, KDF parameters, integrity checks, atomic saves).

## Out of scope

- An attacker with code execution as the same OS user that unlocked the vault. The desktop mode is a
  convenience mode, not hard isolation; run `llmvault-server` on a separate VM, OS account or device
  for that threat (see the threat model in `docs/requirements.html`).
- Unsigned-binary warnings (SmartScreen / Gatekeeper) on preview builds.

## Supported versions

Only the latest release receives security fixes.
