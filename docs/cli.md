# CLI reference

```text
datagrant [--json] [--dsn DSN] [--signing-key FILE] [--hash-key FILE] [--receipt-log FILE] [--receipt-sink URL] [--receipt-sink-mode MODE] [--version] COMMAND ...
```

Run `datagrant COMMAND --help` for the exact flags of your installed version. This page matches v0.3.0.

## Conventions

- **Dry run by default.** Any command that changes something (`keys init`, `request`, `approve`, `revoke`, `sweep`, `preflight`) only reports what it would do unless you pass `--apply`. `--dry-run` is accepted as a no-op. Passing both `--apply` and `--dry-run` exits 2.
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

Key paths resolve in this order: explicit flag, then environment variable, then `keys init --dir`, then the default directory. Every command uses the same resolver.

## Exit codes

| Code | Meaning |
| :---: | --- |
| 0 | Success, including a clean dry run and "nothing to do". |
| 1 | Denied or failed: policy denial (including `max_columns` and `max_concurrent_grants`), invalid policy, failed check, bad receipt chain, database error, keys that already exist, a bad or expired OIDC token, a token-file that cannot be read (missing, symlink, not `0600` on POSIX, too large), or `approve` identity-mode / issuer mismatch. |
| 2 | Usage error: unknown or inapplicable flag, an invalid receipt sink URL, mode or token, `--apply` with `--dry-run`, missing DSN or policy, both keys resolving to the same file, `--as-user` when `identity.mode` is `oidc`, `--oidc-token-file` when `identity.mode` is `local`, a missing OIDC token in `oidc` mode, or an explicit `--pending-ttl` longer than `policy.pending_ttl` in `two-person` mode. |
| 3 | `revoke`/`sweep`: access was removed but a receipt could not be written (including `request_expired` for a pending request that sweep already expired). `request --apply` / `approve --apply`: a `denied` or `not_approved` receipt could not be written, so nothing was issued. `request`/`approve` with a sink: the outbox cursor is unusable, so nothing was issued; or, in `required` mode, the `issued` receipt could not be delivered, so the grant was revoked (the message says if the grant is STILL ACTIVE because that revoke failed). `receipts push --apply`: some receipts are still pending. |
| 4 | `revoke`/`sweep`: a revoke failed. The grant stays active and its role stays locked out; the error is in `last_error`. |

## Commands

### `keys init [--dir DIR] [--signing-key FILE] [--hash-key FILE] [--apply]`
Creates a random hash key and an ed25519 signing key as `0600` files and prints the public key. It refuses to overwrite an existing key (exit 1), and refuses if both paths are the same file (exit 2).

### `keys export-pubkey [--signing-key FILE]`
Prints the public key hex for `receipts verify --pubkey`.

### `policy check FILE`
Validates a policy offline. No database is involved, and no IdP is contacted. If `DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1` and `identity.mode` is `oidc`, it prints a warning that insecure `http://` localhost OIDC URLs are enabled.

### `request --dataset D --table SCHEMA.TABLE --columns C1,C2 --duration 2h --purpose TEXT [--row-filter EXPR] [--pending-ttl 24h] [--policy FILE] [--as-user NAME] [--oidc-token-file FILE] [--apply]`
Resolves the caller ([OIDC identity](#oidc-identity)), then evaluates the request against the policy (including group membership from `policy.groups` plus any `identity.group_map` hits, `max_columns`, and duration). With `approval: auto`, `--apply` creates the masked view and an expiring LOGIN role, writes an `issued` receipt, and prints the connection details and the one-time password. `--pending-ttl` is ignored in `auto` mode. With `approval: two-person`, it creates a pending request and stores `requester_identity`. If `--pending-ttl` is omitted, the lifetime is `min(24h, policy.pending_ttl)` when the cap is set, else `24h`. An explicit `--pending-ttl` longer than `policy.pending_ttl` is exit 2, before any database write. If `max_concurrent_grants` is set, `request` and `approve` count grants with `status = 'active' AND expires_at > now()` for that requester and deny (exit 1) when the cap is already reached. Revoked grants and grants past `expires_at` (swept or not) do not count. A policy or limit refusal on `--apply` writes a `denied` receipt (`details.reasons`, `details.phase: request`, no `grant_id`) and still exits 1; a dry run writes nothing. If that receipt cannot be written, exit 3 and do not create a pending row or grant. Reasons and `purpose` are redacted the same way as other CLI output. Column names that are not in the table's policy are omitted from the receipt (`details.unknown_column_count` and `details.unknown_columns_sha256` of the canonical JSON of those names instead); receipt reasons do not copy the unknown names. `row_filter` is stored only when it exactly matches a policy `row_filters` entry; otherwise it is null with `details.row_filter_sha256` (sha256 of the UTF-8 filter) and `details.row_filter_unlisted`. The requester gets the password now, the database stores only its SCRAM verifier, and no role exists until approval. If the `issued` receipt can't be written, the grant is revoked at once ("no receipt, no access"). Dry runs in `oidc` mode still verify the token.

### `approve REQUEST_ID [--policy FILE] [--as-user NAME] [--oidc-token-file FILE] [--apply]`
Resolves the caller the same way as `request`. A member of an `approvers` group who is not the requester approves a pending request. The policy is re-evaluated at approval time, including `max_columns` and the concurrent-grant cap. In `oidc` mode the pending request must have been created in `oidc` mode with matching `iss` and `username_claim`; self-approval is refused if either the display name or `(iss, sub)` matches. An `--apply` refusal writes a `not_approved` receipt (`details.reasons`, `details.phase: approve`, `details.request_id`, no `grant_id`) and still exits 1; a dry run writes nothing. If that receipt cannot be written, exit 3 and do not create a grant. `purpose`, columns, and `row_filter` on that receipt follow the same redaction and policy-known-values rules as `denied`. `revoke` and `sweep` take no identity flags.

### `grant list [--all]` and `grant status GRANT_ID`
Show active grants (`--all` includes revoked and expired) or one grant, including `last_error`.

### `revoke GRANT_ID [--apply]`
Locks the role out and commits, terminates its sessions, then drops the view and role and records the state. The revoke goes ahead even if the signing key is unavailable (exit 3 in that case).

### `sweep [--apply]`
Revokes every expired grant (`expired` receipts) and expires stale pending requests (`request_expired` receipts on `--apply`, with `details.request_id` and no `grant_id`). Dry runs write nothing. If the expiry receipt cannot be written, the pending row is still expired (access was never granted) and the command exits 3; a later sweep does not write a duplicate. Run it on a schedule, for example every minute.

### `receipts verify [--pubkey HEX|FILE] [--expect-head SHA256] [--sink URL] [--receipt-log FILE] [--signing-key FILE]`
Checks every signature, sequence number and hash link, and reports the first break. It prints the head hash. Record that hash somewhere off the host and pass it back with `--expect-head` to detect truncation of the newest entries.

With `--sink URL` (alias `--receipt-sink`, or `DATAGRANT_RECEIPT_SINK`), it also reads the sink head and compares it with the local chain. It never writes to the sink or the outbox cursor. Equal heads pass. A sink behind the local log passes if the local receipt at the sink's `seq` hashes to the sink head; the rest are reported as not yet delivered. A sink ahead of the local log, or a different hash at the same `seq`, fails (exit 1), as does a sink that can't be reached. It also fails if the sink head is behind the last `seq` the sink acknowledged in `<receipt-log>.sink` (sink lost or replaced), or if that cursor is unreadable, corrupt, or ahead of the local log. `--json` adds `sink_seq`, `sink_head_sha256` and `undelivered` (null when the sink check didn't produce them). If the local chain fails, the sink isn't checked.

### `preflight [--apply]`
Creates datagrant's state schema (with `--apply`) and warns about `PUBLIC` defaults that every grant role inherits: `CONNECT` on other databases, `TEMP` in this database, and `CREATE` in schema `public`. A dry run only reports the warnings.

### `receipts push [--receipt-sink URL] [--receipt-log FILE] [--apply]`
Sends receipts the sink hasn't acknowledged yet (the outbox) to the external sink, in order. A dry run shows how many are pending. The last acknowledged `seq` is kept in `<receipt-log>.sink` (0600). Run it from cron after a sink outage. Exit 3 if anything is still pending.

See [Receipt sink](#receipt-sink) below for how delivery works.

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
