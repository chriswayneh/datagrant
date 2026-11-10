# Changelog

All notable changes to datagrant are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Optional policy limits ([design](docs/design/approvals-policy-limits.md)): `pending_ttl` (`1m`..`7d`) caps an explicit `request --pending-ttl` in two-person mode (exit 2 if the flag is longer; omitted flag uses `min(24h, policy.pending_ttl)`); `max_columns` per table (denied if the unique column count exceeds it; cannot exceed the size of `columns`); `max_concurrent_grants` policy-wide and/or per dataset (minimum of those set; counts `status = 'active' AND expires_at > now()` for that requester on `request` and `approve`; revoked grants and grants past `expires_at`, swept or not, do not count). Omitting the keys keeps v0.3.0 behavior. `policy.version` stays `1`.
- Denial and request-expiry receipts ([design](docs/design/approvals-policy-limits.md)): `request --apply` that is refused writes `denied`; `approve --apply` that is refused writes `not_approved`; `sweep --apply` that expires a pending request writes `request_expired`. Dry runs write nothing. Receipts stay version 1, signed and hash-chained; `grant_id` is omitted. Reasons and `purpose` are redacted like other CLI output. `denied` / `not_approved` keep only policy-listed column names for that table (`details.unknown_column_count` and `details.unknown_columns_sha256` for the rest; receipt reasons do not copy unknown names) and store `row_filter` only when it exactly matches a policy `row_filters` entry (otherwise `row_filter` is null with `details.row_filter_sha256` and `details.row_filter_unlisted`). A denial/`not_approved` receipt that cannot be written is exit 3 and creates no pending row or grant. Sweep still expires the pending row if `request_expired` cannot be written (exit 3); a later sweep does not write a duplicate. `receipts verify` still accepts v0.3.0 logs.

## [0.3.0] - 2026-11-07

Real identity.

### Added
- Optional OIDC identity ([design](docs/design/oidc-identity.md), [policy](docs/policy.md#identity), [CLI](docs/cli.md#oidc-identity), [demo](docs/demo-oidc.md)).
  - `policy.identity.mode: local` (default, including when `identity` is omitted) keeps OS/`--as-user` names. `mode: oidc` requires an ID token on every `request` and `approve`.
  - Token input is `--oidc-token-file` (0600, no symlinks, beats env) or `$DATAGRANT_OIDC_TOKEN`. There is no `--oidc-token` flag. In `oidc` mode `--as-user` is refused (exit 2); a missing token is refused (exit 2). In `local` mode `--oidc-token-file` is refused (exit 2) and `$DATAGRANT_OIDC_TOKEN` is ignored.
  - Verified `username_claim` (default `sub`) becomes the requester or approver. IdP groups grant nothing unless listed in `identity.group_map`. `allowed_groups` is an IdP-side admission gate only.
  - Two-person `approve` checks identity-mode parity (`local` vs `oidc`, exit 1, no name-only fallback), matching `iss` / `username_claim`, and both the display name and `(iss, sub)` so a renamed email cannot self-approve.
  - Receipts stay version 1 with additive `identity` and `approver_identities` (`source`, and for OIDC `iss`, `sub`, `token_sha256`). The raw token is never stored. `revoke` and `sweep` still take no identity.

### Fixed
- CLI error redaction no longer globally replaces a DSN password shorter than 4 characters, which mangled diagnostics (password `er` turned `server error` into `s***v*** ***ror`). `user:pass@` and `password=` forms are still redacted at every length, so a full DSN does not leak its password.

## [0.2.0] - 2026-11-04

Tighter privacy controls and off-host evidence.

### Added
- Per-dataset hash scope. Each dataset now hashes under its own key, derived from the hash key file and the dataset's `hash_scope` (default: the dataset name). Datasets that set the same `hash_scope` share hashes, so values can still be joined across them on purpose.
- `filter_columns` on a table: columns a row filter may use that are never in the grant view and can't be requested. Every filter column must be used by a row filter and may not also be in `columns`.
- External receipt sink ([design](docs/design/receipt-sink.md), [CLI](docs/cli.md#receipt-sink)). Every receipt can also go to an HTTPS webhook (standard library only) or an append-only `file://` sink.
  - Configure with `--receipt-sink`, `--receipt-sink-mode` or `DATAGRANT_RECEIPT_SINK`, `DATAGRANT_RECEIPT_SINK_MODE`; the bearer token comes only from `DATAGRANT_RECEIPT_SINK_TOKEN` and is never printed. Invalid settings exit 2.
  - `best-effort` (default) warns and keeps undelivered receipts in an outbox: the local log plus a 0600 `<receipt-log>.sink` cursor. `required` revokes a grant whose `issued` receipt can't be delivered (exit 3). `revoke` and `sweep` never wait on the sink.
  - New grants are refused (exit 3) if the outbox cursor is unusable.
  - New `receipts push` sends pending receipts (dry run unless `--apply`; exit 3 while any remain).
  - `receipts verify --sink` compares the local chain with the sink head, read-only, and fails on a sink ahead, a hash mismatch, a sink behind its own acknowledgements, a bad cursor or an unreachable sink. `--json` adds `sink_seq`, `sink_head_sha256` and `undelivered`.

### Changed (breaking)
- **Hash outputs differ from v0.1.0.** `hash` masks now use a key derived per dataset (`hash_scope`, default the dataset name). The same value hashes differently than it did under v0.1.0, and differently in each dataset unless datasets share a `hash_scope`. Joins on hashed values across versions or across datasets won't match. To compare with old outputs, re-issue the grant; there is no setting that restores the single unscoped key.

### Changed
- Row filters may now reference `columns` or `filter_columns`; anything else is still a policy error.

## [0.1.0] - 2026-11-02

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
