# CLI reference

```text
datagrant [--json] [--dsn DSN] [--signing-key FILE] [--hash-key FILE] [--receipt-log FILE] [--receipt-sink URL] [--receipt-sink-mode MODE] [--version] COMMAND ...
```

Run `datagrant COMMAND --help` for the exact flags of your installed version. This page matches v0.4.0.

## Conventions

- **Dry run by default.** Any command that changes something (`keys init`, `request`, `approve`, `revoke`, `sweep`, `preflight`) only reports what it would do unless you pass `--apply`. `--dry-run` is accepted as a no-op. Passing both `--apply` and `--dry-run` exits 2. `doctor` is read-only and does not take `--apply`.
- **`--json`** gives machine-readable output and can go before or after the command.
- **Per-command flags.** Each command accepts only the shared flags it uses (see the table below). Using a flag a command doesn't take, for example `policy check --dsn ...`, exits 2.
- **Secrets are never echoed.** DSN `user:pass@` and `password=` forms are redacted from errors at every password length. An extracted DSN password of 4 or more characters is also removed wherever it appears in the message; shorter ones are not globally replaced, so they do not destroy the rest of the text. Sink bearer tokens and OIDC ID tokens are redacted from errors, warnings and JSON. The one-time database password is printed once, to the person it belongs to. There is no `--oidc-token` flag: putting a token on `argv` would leak via `ps` and shell history.

## Environment and defaults

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Admin connection | `--dsn` | `DATAGRANT_DSN` | none (required where used) |
| Policy file | `--policy` | `DATAGRANT_POLICY` | none (required where used) |
| Signing key | `--signing-key` | `DATAGRANT_SIGNING_KEY` | `~/.config/datagrant/signing.key` |
| Hash key | `--hash-key` | `DATAGRANT_HASH_KEY` | `~/.config/datagrant/hash.key` |
| Receipt log | `--receipt-log` | `DATAGRANT_RECEIPT_LOG` | `~/.config/datagrant/receipts.jsonl` |
| External receipt sink (`https://` URL, or `file:///` path) | `--receipt-sink` | `DATAGRANT_RECEIPT_SINK` | none (no sink) |
| Sink mode (`required` or `best-effort`) | `--receipt-sink-mode` | `DATAGRANT_RECEIPT_SINK_MODE` | `best-effort` |
| Sink bearer token | none | `DATAGRANT_RECEIPT_SINK_TOKEN` | none |
| OIDC ID token (`identity.mode: oidc`) | `--oidc-token-file` | `DATAGRANT_OIDC_TOKEN` | none (`--oidc-token-file` beats env) |
| JWKS cache directory | none | `DATAGRANT_JWKS_CACHE_DIR` | `~/.cache/datagrant/jwks` |
| Allow `http://` localhost OIDC URLs | none | `DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1` | unset (https only; test-only when set) |
| Force strict policy-file mode checks | `--strict-policy-permissions` | `DATAGRANT_STRICT_POLICY_PERMISSIONS` | unset or empty (off; a 0644 policy file warns unless the file itself sets `strict_policy_permissions: true`). `1`/`true`/`yes`/`on` (case-insensitive, trimmed) turns the override on. `0`/`false`/`no`/`off` is off. Any other non-empty value is exit 2. |

Key paths resolve in this order: explicit flag, then environment variable, then `keys init --dir`, then the default directory. Every command uses the same resolver.

## Exit codes

| Code | Meaning |
| :---: | --- |
| 0 | Success, including a clean dry run and "nothing to do". |
| 1 | Denied or failed: policy denial (including `max_columns` and `max_concurrent_grants`), invalid policy, failed check, bad receipt chain, database error, keys that already exist, a bad or expired OIDC token, a token-file that cannot be read (missing, symlink, not `0600` on POSIX, too large), `approve` identity-mode / issuer mismatch, `strict_preflight` remaining PUBLIC defaults on access-creating `--apply`, a group/other-accessible receipt log on access-creating `--apply`, a group/other-accessible policy file on access-creating `--apply` when `strict_policy_permissions` is set in the file or forced by `--strict-policy-permissions` / `$DATAGRANT_STRICT_POLICY_PERMISSIONS`, or `request`/`approve --apply` when the admin cannot `SET log_statement`. |
| 2 | Usage error: unknown or inapplicable flag, an invalid receipt sink URL, mode or token, `--apply` with `--dry-run`, missing DSN or policy (except `doctor`, which reports these as failed checks, exit 1), both keys resolving to the same file, `--as-user` when `identity.mode` is `oidc`, `--oidc-token-file` when `identity.mode` is `local`, a missing OIDC token in `oidc` mode, an explicit `--pending-ttl` longer than `policy.pending_ttl` in `two-person` mode, or `$DATAGRANT_STRICT_POLICY_PERMISSIONS` set to a value other than `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`. |
| 3 | `revoke`/`sweep`: access was removed but a receipt could not be written (including `request_expired` for a pending request that sweep already expired, and a group/other-accessible receipt log: those commands warn, still revoke, then exit 3). `request --apply` / `approve --apply`: a `denied`, `not_approved`, or `approval_recorded` receipt could not be written, so nothing was issued (a failed `approval_recorded` write also removes that caller's vote). `request`/`approve`/`preflight --apply`: another session still holds the datagrant advisory lock after the wait bound, so nothing was issued. `request`/`approve` with a sink: the outbox cursor is unusable, so nothing was issued; or, in `required` mode, the `issued` receipt could not be delivered, so the grant was revoked (the message says if the grant is STILL ACTIVE because that revoke failed). `receipts push --apply`: some receipts are still pending. |
| 4 | `revoke`/`sweep`: a revoke failed. The grant stays active and its role stays locked out; the error is in `last_error`. |

## Commands

### `keys init [--dir DIR] [--signing-key FILE] [--hash-key FILE] [--apply]`
Creates a random hash key and an ed25519 signing key as `0600` files and prints the public key. It refuses to overwrite an existing key (exit 1), and refuses if both paths are the same file (exit 2).

### `keys export-pubkey [--signing-key FILE]`
Prints the public key hex for `receipts verify --pubkey`.

### `policy check FILE`
Validates a policy offline. No database is involved, and no IdP is contacted. If `DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1` and `identity.mode` is `oidc`, it prints a warning that insecure `http://` localhost OIDC URLs are enabled.

### `request --dataset D --table SCHEMA.TABLE --columns C1,C2 --duration 2h --purpose TEXT [--row-filter EXPR] [--pending-ttl 24h] [--policy FILE] [--as-user NAME] [--oidc-token-file FILE] [--apply]`
If `strict_preflight` is true, `--apply` exits 1 when PUBLIC preflight warnings remain (dry run still reports them). A group/other-accessible receipt log is refused on `--apply` (exit 1) before any grant is created. A 0644 policy file warns; with `strict_policy_permissions: true`, `--apply` refuses. `--strict-policy-permissions` or `$DATAGRANT_STRICT_POLICY_PERMISSIONS=1` forces that refusal from outside the file and checks the mode before the YAML is parsed. `--apply` also refuses (exit 1) if the admin role cannot `SET log_statement` (superuser, or PostgreSQL 15+ `GRANT SET ON PARAMETER log_statement`). When it can, `apply_plan` issues `SET LOCAL log_statement = 'none'` in the grant transaction so passwords and hash-key parameters are not captured in the server log.

Resolves the caller ([OIDC identity](#oidc-identity)), then evaluates the request against the policy (including group membership from `policy.groups` plus any `identity.group_map` hits, `max_columns`, and duration). With `approval: auto`, `--apply` creates the masked view and an expiring LOGIN role, writes an `issued` receipt, and prints the connection details and the one-time password. `--pending-ttl` is ignored in `auto` mode. With `approval: two-person`, it creates a pending request and stores `requester_identity`. If `--pending-ttl` is omitted, the lifetime is `min(24h, policy.pending_ttl)` when the cap is set, else `24h`. An explicit `--pending-ttl` longer than `policy.pending_ttl` is exit 2, before any database write. If `max_concurrent_grants` is set, `request` and `approve` count grants with `status = 'active' AND expires_at > now()` for that requester and deny (exit 1) when the cap is already reached. Revoked grants and grants past `expires_at` (swept or not) do not count. A policy or limit refusal on `--apply` writes a `denied` receipt (`details.reasons`, `details.phase: request`, no `grant_id`) and still exits 1; a dry run writes nothing. If that receipt cannot be written, exit 3 and do not create a pending row or grant. Reasons and `purpose` are redacted the same way as other CLI output. Column names that are not in the table's policy are omitted from the receipt (`details.unknown_column_count` instead); receipt reasons do not copy the unknown names. `row_filter` is stored only when it exactly matches a policy `row_filters` entry; otherwise it is null with `details.row_filter_unlisted`. Unknown names and unlisted filters are not hashed onto the receipt. The requester gets the password now, the database stores only its SCRAM verifier, and no role exists until approval. If the `issued` receipt can't be written, the grant is revoked at once ("no receipt, no access"). Dry runs in `oidc` mode still verify the token.

### `approve REQUEST_ID [--policy FILE] [--as-user NAME] [--oidc-token-file FILE] [--apply]`
`--apply` refuses (exit 1) if the admin cannot `SET log_statement`, same as `request`. Resolves the caller the same way as `request`. A member of an `approvers` group who is not the requester approves a pending request (including OIDC `group_map`-only members). The policy is re-evaluated at approval time, including `max_columns`, the concurrent-grant cap, and optional `distinct-groups` SoD. `distinct-groups` refuses (exit 1, `not_approved` on `--apply`) when requester groups ∩ approver groups ∩ the table's `allowed_groups` is non-empty; dry runs write nothing. Groups are static `policy.groups` plus `group_map` extras (`mapped_groups` and remapped requester IdP groups). In `oidc` mode the pending request must have been created in `oidc` mode with matching `iss` and `username_claim`; self-approval is refused if either the display name or `(iss, sub)` matches. When `approvals_required` is N (default 1), the grant is created only on the Nth distinct approval; earlier `--apply` votes leave the row pending, print `approvals N/M`, and write `approval_recorded` from the counted votes only (`details.request_id`, `details.approvals_recorded`, `details.approvals_required`, no `grant_id`). A second vote from the same person is idempotent (exit 0, no extra receipt) unless counted votes already meet N, in which case that caller proceeds to issue. A stored vote that no longer counts is replaced in place rather than appended. The Nth vote and the grant are one transaction inside `apply_plan` (`FOR UPDATE`, merge only the caller's new vote with the locked row, re-check, claim); that commit happens first, then the `issued` receipt, then sink delivery, as in v0.3.0. If apply fails, the vote is not stored. If the locked counted names do not match the plan's approvers (a vote was dropped or replaced between snapshot and claim), apply fails closed, rolls back, writes no grant, and leaves the request pending so the caller can retry. Issued receipts never name an approver who is not in that locked counted set. A required-sink failure revokes the committed grant (STILL ACTIVE only if that revoke failed). Votes are stamped with the current `policy.sha256`, OIDC `iss`, and the caller's `mapped_groups` from the verified token; counting uses those groups with `can_approve`. After a policy edit, votes that do not match that stamp or that fail `can_approve` are not counted (`ignored_approvals` in JSON) and do not contribute to N. If `approval_recorded` cannot be written, that caller's vote is removed (not necessarily the newest) and the command exits 3. An `--apply` refusal writes a `not_approved` receipt (`details.reasons`, `details.phase: approve`, `details.request_id`, no `grant_id`) and still exits 1; a dry run writes nothing and reports whether this caller would be a partial vote or the issuing vote. If a `not_approved` receipt cannot be written, exit 3 and do not create a grant. `purpose`, columns, and `row_filter` on denial and `approval_recorded` receipts follow the same redaction and policy-known-values rules as `denied`. `revoke` and `sweep` take no identity flags. Partial votes still expire with `pending_ttl` (`request_expired`); approvals do not extend TTL.

### `grant list [--all]` and `grant status GRANT_ID`
Show active grants (`--all` includes revoked and expired) or one grant, including `last_error`. JSON includes `approvals` as `N/M` from the recorded `approvers` list (after issue, N equals M).

### `revoke GRANT_ID [--apply]`
Locks the role out and commits, terminates its sessions, then drops the view and role and records the state. The revoke goes ahead even if the signing key is unavailable (exit 3 in that case). `strict_preflight` never blocks revoke. A group/other-accessible receipt log is a warning: access is still removed, then exit 3 (receipt problem). Missing `SET log_statement` privilege does not block revoke.

### `sweep [--apply]`
Revokes every expired grant (`expired` receipts) and expires stale pending requests (`request_expired` receipts on `--apply`, with `details.request_id` and no `grant_id`). Dry runs write nothing. Missing `SET log_statement` privilege does not block sweep. If the expiry receipt cannot be written, the pending row is still expired (access was never granted) and the command exits 3; a later sweep does not write a duplicate. Run it on a schedule, for example every minute.

### `receipts verify [--pubkey HEX|FILE] [--expect-head SHA256] [--sink URL] [--receipt-log FILE] [--signing-key FILE]`
Checks every signature, sequence number and hash link, and reports the first break. It prints the head hash. Record that hash somewhere off the host and pass it back with `--expect-head` to detect truncation of the newest entries.

With `--sink URL` (alias `--receipt-sink`, or `DATAGRANT_RECEIPT_SINK`), it also reads the sink head and compares it with the local chain. It never writes to the sink or the outbox cursor. Equal heads pass. A sink behind the local log passes if the local receipt at the sink's `seq` hashes to the sink head; the rest are reported as not yet delivered. A sink ahead of the local log, or a different hash at the same `seq`, fails (exit 1), as does a sink that can't be reached. It also fails if the sink head is behind the last `seq` the sink acknowledged in `<receipt-log>.sink` (sink lost or replaced), or if that cursor is unreadable, corrupt, or ahead of the local log. `--json` adds `sink_seq`, `sink_head_sha256` and `undelivered` (null when the sink check didn't produce them). If the local chain fails, the sink isn't checked.

### `doctor [--policy FILE] [--strict-policy-permissions]`
Read-only host and database checks, in order: key files, policy parse, POSIX policy-file mode (warn if group/other-accessible; fails when `strict_policy_permissions` is true in the file or when `--strict-policy-permissions` / `$DATAGRANT_STRICT_POLICY_PERMISSIONS` is set), receipt-log and sink-cursor file mode on POSIX, DSN connect, `preflight` PUBLIC warnings (warn, does not fail), `pg_signal_backend` membership or superuser, ability to `SET log_statement` (superuser, or PostgreSQL 15+ `has_parameter_privilege`; PostgreSQL 14 and earlier require superuser), receipt-log chain head, optional sink cursor readability. Group/other-writable is the stronger policy-file finding (worded `group/other-accessible`). Extra warnings: file not owned by the current user, or a group/other-writable parent directory. With `--strict-policy-permissions` or `$DATAGRANT_STRICT_POLICY_PERMISSIONS=1`, a group/other-accessible policy file fails the permissions check and is not parsed. Exit 0 if every check passes; exit 1 if any check fails (warnings are not failures); exit 2 on usage. A missing DSN, policy, or key is a failed check (exit 1), not a usage error. `--json` lists each check as `{name, status, detail}`. Does not take `--apply`, does not create schemas, keys, or grants, does not `SET log_statement`, and does not take the advisory lock.

### `preflight [--policy FILE] [--apply]`
Creates datagrant's state schema (with `--apply`) and warns about `PUBLIC` defaults that every grant role inherits: `CONNECT` on other databases, `TEMP` in this database, and `CREATE` in schema `public`. A dry run only reports the warnings and does not read a policy file. `--apply` reads `--policy` or `$DATAGRANT_POLICY` for `strict_preflight` (and policy-file mode). If the policy sets `strict_preflight: true`, `--apply` still creates datagrant state, then exits 1 when those PUBLIC warnings remain (`revoke` and `sweep` ignore this key). Without a policy path, `--apply` cannot honor `strict_preflight`. `--strict-policy-permissions` / `$DATAGRANT_STRICT_POLICY_PERMISSIONS=1` on `--apply` refuses a group/other-accessible policy file before parsing it.

### `receipts push [--receipt-sink URL] [--receipt-log FILE] [--apply]`
Sends receipts the sink hasn't acknowledged yet (the outbox) to the external sink, in order. A dry run shows how many are pending. The last acknowledged `seq` is kept in `<receipt-log>.sink` (0600). Run it from cron after a sink outage. Exit 3 if anything is still pending.

See [Receipt sink](#receipt-sink) below for how delivery works.

## Receipt events

`RECEIPT_VERSION` stays 1. `receipts verify` still accepts v0.3.0 logs. Dry runs write nothing. Events added in v0.4.0 omit `grant_id`. Reasons and `purpose` are redacted like other CLI output. `denied` / `not_approved` / `approval_recorded` keep only policy-listed column names (`details.unknown_column_count` for the rest) and store `row_filter` only when it exactly matches a listed filter (otherwise null plus `details.row_filter_unlisted`).

| Event | When | Notes |
| --- | --- | --- |
| `issued` | Grant created | `grant_id` set; sink delivery follows the sink mode |
| `revoked` / `expired` / `revoke_failed` | Revoke or sweep of a grant | Unchanged from v0.3.0 |
| `denied` | `request --apply` refused by policy or limits | `details.phase: request`, `details.reasons`; no `grant_id` |
| `not_approved` | `approve --apply` refused | `details.phase: approve`, `details.request_id`, `details.reasons`; no `grant_id` |
| `approval_recorded` | Quorum vote that did not yet issue | `details.request_id`, `details.approvals_recorded`, `details.approvals_required`; counted votes only; no `grant_id` |
| `request_expired` | `sweep --apply` expires a pending request | `details.request_id`; no `grant_id` |

## OIDC identity

Optional. Design: [design/oidc-identity.md](design/oidc-identity.md). Policy: [policy.md#identity](policy.md#identity). Walkthrough: [demo-oidc.md](demo-oidc.md). Since v0.3.0.

**Token acquisition.** datagrant never talks to the IdP token endpoint, never runs a browser login, and never refreshes a token. The caller obtains a short-lived OpenID Connect **ID token** from their issuer (device code, authorization code, workload identity, CI OIDC, or a test mint) and presents it. Access tokens are not ID tokens: verification requires `iss`, `sub`, `aud`, `exp` and `iat` as ID token claims.

**How the caller is named.**

| `policy.identity.mode` | Caller name | Groups used for allow/approve |
| --- | --- | --- |
| `local` (default, including omitted `identity`) | OS user, or `--as-user` | Static `policy.groups` only |
| `oidc` | Verified `username_claim` (default `sub`) | Static `policy.groups` of that name, plus IdP groups translated through `identity.group_map` |

IdP groups whose names happen to match a `policy.groups` entry still grant nothing until `group_map` says so. `identity.allowed_groups` only gates whether the token is accepted.

**Safe token input.** `--oidc-token-file` beats `$DATAGRANT_OIDC_TOKEN`. The file is opened `O_RDONLY | O_NOFOLLOW`, must be a regular file, must be `0600` on POSIX, at most 16 KiB, ASCII compact JWT, trailing whitespace stripped. `"-"` (stdin) is refused. A path that looks like a pasted JWT is not echoed. The raw token is redacted (`***`) from errors, warnings and JSON, and receipts store `token_sha256` (sha256 of the compact JWT) rather than the token.

**Mode conflicts (before database work for the flag checks):**

| Situation | Exit |
| --- | :---: |
| `--as-user` when `identity.mode` is `oidc` | 2 |
| Missing `--oidc-token-file` and empty `$DATAGRANT_OIDC_TOKEN` in `oidc` mode | 2 |
| `--oidc-token-file` when `identity.mode` is `local` | 2 |
| `$DATAGRANT_OIDC_TOKEN` set in `local` mode | ignored (not an error) |
| Token file missing, symlink, group/other-readable on POSIX, not a regular file, or larger than 16 KiB | 1 |
| Bad signature, wrong `iss`/`aud`, expired, `iat` older than `max_token_age`, discovery/JWKS failure | 1 |
| `approve` when pending request mode is not the current policy mode (`local` vs `oidc`) | 1 |
| `approve` in `oidc` mode when stored `iss` or `username_claim` does not match the current policy | 1 |

Discovery fetches `<issuer without trailing slash>/.well-known/openid-configuration` over HTTPS (5 s connect, 10 s deadline, no redirects, TLS verified). JWKS is cached under `$DATAGRANT_JWKS_CACHE_DIR` (default `~/.cache/datagrant/jwks`), directory `0700`, files `0600`, keyed by `sha256(issuer)`, default TTL `5m`.

`--json` on a successful `request`/`approve` includes `identity_source` (`os`, `flag` or `oidc`). Issued receipts add `identity` and, after two-person approval, `approver_identities`.

## Receipt sink

An external receipt sink keeps an off-host copy of every receipt, so deleting or rewriting the newest local receipts is caught without a hand-recorded head hash. Design: [design/receipt-sink.md](design/receipt-sink.md). Since v0.2.0.

**Configuration.** No sink configured means v0.1.0 behavior.

| Setting | Flag | Environment | Notes |
| --- | --- | --- | --- |
| Sink URL | `--receipt-sink` (`--sink` on `receipts verify`) | `DATAGRANT_RECEIPT_SINK` | `https://host/path`, or `file:///absolute/path`. Plain `http://` only for `localhost` and `127.0.0.1`. URLs with credentials, a query or a fragment are refused. |
| Mode | `--receipt-sink-mode required\|best-effort` | `DATAGRANT_RECEIPT_SINK_MODE` | Default `best-effort`. Only `request`, `approve`, `revoke` and `sweep` take the flag. |
| Bearer token | none | `DATAGRANT_RECEIPT_SINK_TOKEN` | Printable ASCII without spaces. Never accepted on the command line and never printed. |

Bad settings exit 2 before any database work. Flags beat the environment.

**Webhook.** `POST <url>` with `Content-Type: application/x-ndjson` and one signed receipt line per request; any 2xx is success. `GET <url>/head` returns `{"seq": N, "head_sha256": "..."}`, or 404 when empty. 5 s connect timeout and a 10 s wall-clock limit per request. Retries after 0.5, 1 and 2 s on network errors, 5xx, 408 and 429; other 4xx are refusals and aren't retried. Redirects are never followed. The receiver should refuse a different line at a `seq` it already has.

**File sink.** Appends to the file (created 0600, no symlinks, must stay private), locked like the receipt log. Lines must arrive in `seq` order; an identical resend is a no-op and a different line at a used `seq` is refused.

**Delivery and modes.**

| Command | `best-effort` | `required` |
| --- | --- | --- |
| `request --apply`, `approve --apply` | Checks the outbox cursor first (exit 3, nothing issued, if it's unusable). Sends the `issued` receipt with retries. On failure: warning, the grant stands, the receipt stays pending. | Same check first. On failure: the grant is revoked and the command exits 3. |
| `revoke --apply`, `sweep --apply` | Access is removed first, then one delivery attempt without retries. A failure only warns; the exit code doesn't change. `--json` adds `sink` with `delivered`, `pending` and `error`. | Same. Revokes never wait on the sink. |

**Outbox and cursor.** The outbox is the local receipt log plus `<receipt-log>.sink`, a 0600 file (no symlinks) holding `{"acked_seq": N}`, the last `seq` the sink acknowledged. Lines after it are pending. The cursor advances only after a successful delivery and is replaced atomically; a crash in between just resends a line, which sinks treat as a no-op. Flushes are serialized on `<receipt-log>.sink.lock` (not on Windows). A cursor that is corrupt, not private, or ahead of the local log stops new grants (exit 3) until it's fixed.

**`receipts push`.** Dry run by default: prints how many receipts are pending. With `--apply` it sends them in order and exits 3 if any remain. `--json`: `delivered`, `pending`, `error`.

**`receipts verify --sink`.** Read-only; it never writes the cursor or the sink. After the local chain verifies:

| Situation | Result |
| --- | --- |
| Sink head equals the local head | OK, `undelivered` 0 |
| Sink behind, and the local receipt at its `seq` hashes to its head | OK, `undelivered` > 0 |
| Sink empty and nothing acknowledged | OK, every receipt `undelivered` |
| Sink ahead of the local log | Exit 1: local log truncated or replaced |
| Different hash at the sink's `seq` | Exit 1: local log or sink rewritten |
| Sink head behind the cursor's `acked_seq` | Exit 1: sink lost or replaced |
| Cursor unreadable, corrupt, or ahead of the log | Exit 1 (fails closed) |
| Sink unreachable | Exit 1; the local result is still printed |

`--json` adds `sink_seq`, `sink_head_sha256` and `undelivered`.

## Who can use which shared flag

| Command | `--dsn` | `--signing-key` | `--hash-key` | `--receipt-log` | `--receipt-sink` | `--receipt-sink-mode` | `--as-user` / `--oidc-token-file` | `--apply` |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `keys init` | | ✓ | ✓ | | | | | ✓ |
| `keys export-pubkey` | | ✓ | | | | | | |
| `policy check` | | | | | | | | |
| `request`, `approve` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `grant list`, `grant status` | ✓ | | | | | | | |
| `revoke`, `sweep` | ✓ | ✓ | | ✓ | ✓ | ✓ | | ✓ |
| `receipts verify` | | ✓ | | ✓ | ✓ | | | |
| `receipts push` | | | | ✓ | ✓ | | | ✓ |
| `preflight` | ✓ | | | | | | | ✓ |
| `doctor` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | |
