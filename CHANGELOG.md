# Changelog

All notable changes to datagrant are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - Unreleased

First usable version: expiring, masked, receipted Postgres access from the command line.

### Added
- Project scaffolding: package skeleton with `datagrant --version`, CI (lint, type, test), and AI-DLC artifact folders.
- Policy file loader, strict schema validation, and a deny-by-default evaluator with reasons (U1). Example `examples/policy.yaml`. Adds runtime dependency PyYAML.
- Postgres grant engine (U2): a per-grant `security_barrier` view of the allowed columns and rows; a `LOGIN` role with `VALID UNTIL` and a one-time password (only the SCRAM verifier is sent); a grant state table; a safe row-filter grammar; a database-match check; and `PUBLIC`-privilege preflight warnings. Adds runtime dependency psycopg 3.
- Column masking (U3): `redact`, typed `null`, `partial` (last 4 characters, at length 8 or more) and keyed `hash` (pgcrypto HMAC with a key derived from a local key file). Column types are read from the catalog. Fails closed without pgcrypto or the key.
- Revoke and expiry sweep (U4): a lockout is committed before sessions are terminated, then the view and role are dropped and the state is recorded. A failed revoke leaves the role locked out and records `last_error`.
- Signed receipts (U5): canonical JSON signed with ed25519 and hash-chained, for `issued`, `revoked`, `expired` and `revoke_failed` events. Includes `receipts verify` with `--expect-head`, and "no receipt, no access". Adds runtime dependency cryptography.
- CLI (U6): `keys`, `policy check`, `request`, `approve` (two-person mode), `grant list|status`, `revoke`, `sweep`, `receipts verify`, `preflight`. Commands are dry runs by default (`--apply` to act), `--json` works anywhere, flags are per-command, and exit codes are 0–4.
- One-command demo (U7): `make demo` runs a throwaway Postgres pinned by digest, bound to localhost, with automatic teardown. `DATAGRANT_DEMO_DSN` runs it against a scratch database. CI runs the demo both ways.
- Documentation (U8): README, policy, CLI and security references, operations pointer, roadmap, and v0.1.0 release notes.

### Security
- Grant DDL runs with a pinned `search_path` and `pg_catalog`-qualified built-ins.
- Key files are opened with `O_NOFOLLOW` and checked to be private regular files. `keys init` refuses to overwrite a key or to use one file for both keys.
- DSN passwords are redacted from error output.
