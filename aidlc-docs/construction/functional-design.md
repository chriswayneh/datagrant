# Functional design

## U1 — Policy loader and evaluator

**Status:** In progress (Construction start approved 2026-11-02 5:26 PM CT; see ../audit.md). Module: `src/datagrant/policy.py`. Example: `examples/policy.yaml`.

### Policy schema (version 1, YAML via a strict SafeLoader subclass, ≤1 MB; rejects anchors/aliases, duplicate keys, and deep nesting)
| Key | Type | Notes |
| --- | --- | --- |
| `version` | int | Must be `1` |
| `approval` | `auto` \| `two-person` | Default `auto` |
| `max_duration` | `30m`/`4h`/`1d` | Policy-wide cap |
| `groups` | map group → [requesters] | Requester groups |
| `datasets[]` | `name`, `database`, `tables[]` | Unique names; Postgres identifier checks |
| `tables[]` | `name` (`schema.table`), `allowed_groups`, `columns` (col → mask), `row_filters[]`, `require_row_filter`, `max_duration` | Table cap ≤ policy cap; inherits it if absent |

Masks: `passthrough`, `redact`, `hash`, `partial`, `null`. Unknown keys are errors (catches typos).

### Evaluation (`evaluate(policy, request) -> Decision`)
Deny by default; all failing checks are reported: dataset/table exists, requester in an allowed group, columns allowed and unique, purpose present, 0 < duration ≤ table max, row filter required/exactly one of the allowlisted filters. Allowed decisions carry the per-column mask plan, approval mode, and policy SHA-256 (for receipts).

### Errors
`PolicyError` with a path like `policy.datasets[0].tables[1].columns.ssn`. No data values are read or logged.

### Out of U1
SQL generation, filter parsing (filters are matched against an allowlist only; U2 validates/quotes them), CLI wiring (U6).

## U2 — Grant engine (Postgres view + expiring role + grant state)

**Status:** In progress (approved 2026-11-02 5:35 PM CT; see ../audit.md). Modules: `src/datagrant/rowfilter.py`, `src/datagrant/pg/{grant,scram}.py`.

- **Setup:** `ensure_state(conn)` creates schemas `datagrant` (state) and `datagrant_views` (grant views), both `REVOKE ALL … FROM PUBLIC`, and table `datagrant.grants` (id, role, view, dataset, table, requester, purpose, columns, row filter, approval, policy SHA-256, created/expires, status). No passwords or data values stored. Returns `preflight(conn)` warnings.
- **Plan (pure):** `build_plan(decision, request, database=…, password=…)` → `CREATE ROLE dg_<12hex> LOGIN NOINHERIT … PASSWORD <SCRAM verifier> VALID UNTIL <expiry>`; `CREATE VIEW datagrant_views.g_<id> WITH (security_barrier) AS SELECT <allowed cols> FROM schema.table [WHERE filter]`; revoke PUBLIC; grant schema USAGE + SELECT on the view only; insert state row. Every name/value via `psycopg.sql.Identifier`/`Literal`.
- **Password:** `new_password()` (256-bit, URL-safe) is returned once to the caller; only a client-computed SCRAM-SHA-256 verifier is sent, so plaintext never appears in server logs.
- **What a grant role gets — exactly:** explicitly, `USAGE` on schema `datagrant_views` and `SELECT` on its one view; nothing on base tables or `datagrant.*`. Implicitly, whatever Postgres grants to `PUBLIC`: by default `CONNECT` and `TEMP` on every database, `EXECUTE` on functions, read access to system catalogs, and (Postgres ≤14 only) `CREATE` on schema `public`. datagrant does not change these server-wide defaults.
- **Preflight:** `preflight(conn)` warns when `PUBLIC` can `CONNECT` to any other database, create `TEMP` tables in the current one, or `CREATE` in schema `public`.
- **Admin hardening (recommended, done by the DBA):** for each database grant roles must not reach, `REVOKE CONNECT, TEMP ON DATABASE <db> FROM PUBLIC` (then grant `CONNECT` explicitly to real users/groups); in the dataset database `REVOKE TEMP ON DATABASE <db> FROM PUBLIC` and `REVOKE CREATE ON SCHEMA public FROM PUBLIC`. Integration test verifies a grant role cannot connect to a second database after hardening. See ../operations/runbook.md.
- **Row filters:** policy filters may reference only columns listed in the table's `columns` (so filter columns are visible to the grantee) and must parse under a small grammar (`col op literal`, `IS [NOT] NULL`, AND/OR, parentheses; ≤1000 chars, depth ≤16) at policy load; re-emitted as composed SQL. Request must match an allowlisted filter exactly (U1).
- **Masks:** see U3.
- **Apply:** `apply_plan(conn, plan)` first checks `current_database()` equals the dataset's `database` (refuses on mismatch), then runs all statements in one transaction; any error rolls back and raises `GrantError` (SQLSTATE only, no data).
- **Not in U2:** revocation/sweep (U4), receipts (U5), CLI (U6), two-person approval (refused for now).
- **Known limits:** view runs with the admin owner's privileges (base-table RLS not applied to grantee); `VALID UNTIL` blocks new logins only — live sessions are ended by sweep (U4).

## U3 — Masking

**Status:** In progress (approved 2026-11-02 5:43 PM CT; see ../audit.md). Modules: `src/datagrant/pg/mask.py`, `src/datagrant/keys.py`.

- **Catalog:** `inspect_table(conn, "schema.table")` reads column types (`pg_attribute`/`pg_type`) and the pgcrypto schema (`pg_extension`). Unknown columns fail closed.
- **Expressions** (all `psycopg.sql`, each aliased to the original column name):

| Mask | Grantee sees | SQL shape |
| --- | --- | --- |
| `passthrough` | raw value | `"col"` |
| `null` | typed NULL (column keeps its type) | `CAST(NULL AS "schema"."type")` |
| `redact` | `[REDACTED]` for every row (text) | constant |
| `partial` | `*` for all but the last 4 chars if length ≥ 8; all `*` otherwise; NULL stays NULL (length is revealed) | `repeat('*', …) \|\| right(v, 4)` |
| `hash` | hex HMAC-SHA256 of the value as text; NULL stays NULL | `encode(<pgcrypto>.hmac(convert_to(v,'UTF8'), (SELECT key FROM datagrant.hash_keys WHERE id = '<key id>'), 'sha256'), 'hex')` |

- **Hash key:** local file (`~/.config/datagrant/hash.key`, or path in `$DATAGRANT_HASH_KEY`), ≥32 bytes hex, must be `0600` on POSIX. datagrant derives a key (HMAC-SHA256 with a fixed label) and stores only the derived key in `datagrant.hash_keys` (no PUBLIC access), inserted with bound parameters. Views reference it by key id via a subquery that runs with the view owner's rights, so the key is never in a view definition or statement text, and the grantee cannot read it. Same key ⇒ same hash across grants (joinable); new key ⇒ new hashes.
- **Fail closed:** hash mask without pgcrypto in the database, or without a key file → `GrantError`, nothing created.
- **Known limits:** (1) the derived key sits in `datagrant.hash_keys`, readable by superusers/the datagrant admin role; (2) with `log_statement = all` or `log_min_duration_statement`, Postgres logs bound parameters, which would include the derived key on first insert — keep statement logging off for the admin role (`ALTER ROLE <admin> SET log_statement = 'none'`); (3) the grantee needs `EXECUTE` on pgcrypto `hmac` (PUBLIC by default); (4) hashing low-entropy values is only as strong as the key's secrecy; (5) `partial` and `redact` change the column type to text.

## U4 — Expiry, revoke, sweep (`pg/revoke.py`)

- **`revoke(conn, grant_id, reason="manual")`**, three short transactions, each under `SET LOCAL search_path = pg_catalog, pg_temp`:
  1. **Lockout (committed first):** lock the `datagrant.grants` row (`FOR UPDATE`); if not `active`, no-op. Otherwise `ALTER ROLE … NOLOGIN VALID UNTIL 'epoch' PASSWORD NULL` and commit, so the postmaster refuses new logins before any session is killed. (Inside an uncommitted transaction, a reconnect loop could keep logging in; Red Team M1.)
  2. **Terminate:** `pg_terminate_backend` every session of the role in any database and wait (≤5 s) until `pg_stat_activity` shows none.
  3. **Drop:** re-lock and re-check the row, re-terminate any stragglers, `DROP VIEW IF EXISTS`, `REASSIGN OWNED BY role TO CURRENT_USER` + `DROP OWNED BY role`, `DROP ROLE`, then set `status` (`revoked` for manual, `expired` for sweep), `revoked_at`, `revoke_reason` (`manual|expired`) and clear `last_error`.
- **`sweep(conn)`**: selects active grants with `expires_at <= now()` and revokes each in its **own** transaction, so one stuck grant doesn't block the rest. Re-running is a no-op.
- **Fail-safe:** any error (termination refused, sessions not gone, dependent objects, role owns objects in another database) rolls back the failing step; a separate transaction records `last_error`/`last_error_at`. Once step 1 has committed, the role **stays locked out** (no login, no password, expired) even though the grant remains `active`. That's intended: access is never restored by a failed revoke. Status stays `active`, so the next sweep retries. The result is `failed` (CLI in U6 exits non-zero). A grant is only marked revoked when the view and role are actually gone.
- **State migration:** `ensure_state` adds `revoked_at`, `revoke_reason`, `last_error`, `last_error_at` with `ADD COLUMN IF NOT EXISTS` (safe on U2/U3 databases).
- **Admin permissions:** terminating another role's backends needs superuser or membership in `pg_signal_backend`. Without it revoke fails closed (reported, retried).
- **Known limits:** `DROP OWNED` covers only the current database; if a grant role was given objects or privileges in another database, `DROP ROLE` fails and is reported. Receipts for revoke/expire events come in U5.

## U5 — Signed access receipts (`receipt.py`, `keys.py`)

- **Keys:** `init_keys(dir=None)` creates `hash.key` (32 random bytes, hex) and `signing.key` (ed25519 32-byte seed, hex), each `O_CREAT|O_EXCL` mode 0600 in a 0700 directory. It refuses to overwrite either key. Paths come from `$DATAGRANT_HASH_KEY` / `$DATAGRANT_SIGNING_KEY` (file paths) or `~/.config/datagrant/`. Both keys are read through the same hardened reader (`O_NOFOLLOW`, `fstat` on the fd, owner-only, ≤1 KB). Key id = first 16 hex chars of SHA-256 of the raw public key. The public key is exported as 64 hex chars (`SigningKey.public_hex()`).
- **Receipt line:** canonical JSON (sorted keys, no whitespace, UTF-8; floats/NaN rejected; any key named password/key/secret/hash_key/derived/private_key rejected) of `{"receipt": body, "sig": ed25519(canonical(body))}`.
- **Body:** version, event (`issued|revoked|expired|revoke_failed`), event_at (UTC `Z`), host, grant_id, requester, dataset, table, columns with mask types, row_filter, purpose, starts_at, expires_at, policy_sha256, policy_version, approval mode, approvers (empty in auto mode; filled by two-person mode in U6), details (reason, sessions_terminated, or error), seq, prev_receipt_sha256 (SHA-256 of the previous line; 64 zeros first), key_id. No passwords or key material.
- **Log:** local JSONL (`$DATAGRANT_RECEIPT_LOG` or `~/.config/datagrant/receipts.jsonl`), opened `O_APPEND|O_CREAT|O_NOFOLLOW` 0600 and checked on the fd. Writers take `flock` (POSIX; Windows assumes a single writer). Each write is fsync'd. Appending is refused if the last line is partial or not a receipt.
- **Verify:** `verify(log, pubkey, expect_head=None)` checks, for every line: canonical form, key id, signature, `seq`, and the hash link. It reports the first break (line number + reason) and returns the head hash. Edits, deletions and reordering are detected. Truncating the newest lines is only detectable against an externally recorded head hash (`expect_head`).
- **Hooks:** `apply_plan(conn, plan, receipts=ReceiptSink(...))` writes `issued` after commit. `revoke`/`sweep(…, receipts=…)` write `revoked`/`expired`, or `revoke_failed` on every failed attempt (so a stuck grant produces one per sweep). No-ops write nothing. Facts for revoke receipts come from `datagrant.grants` (new columns `masks`, `policy_version`, `approvers`).
- **Fail-safe decisions:** *No receipt, no access.* If the `issued` receipt can't be written, the grant is revoked at once and `GrantError` is raised. A revoke never depends on its receipt: access is removed first, and a receipt write failure is returned as `RevokeResult.receipt_error` (U6 exits non-zero; state in `datagrant.grants` still records it).

## U6 — CLI and two-person approval (`cli.py`, `pg/requests.py`)

- **Commands:** `keys init | export-pubkey`, `policy check <file>`, `request`, `approve <request-id>`, `grant list [--all] | status <id>`, `revoke <id>`, `sweep`, `receipts verify [--pubkey] [--expect-head]`, `preflight`. `--json` works on every command, before or after the subcommand.
- **Dry run by default (QE):** `keys init`, `request`, `approve`, `revoke`, `sweep` and `preflight` change nothing unless `--apply` is given. Without it they print what would happen and exit 0:
  - plan SQL with `PASSWORD '<redacted>'` for `request` and `approve`; no password is generated and no verifier is shown;
  - the grant's state and open session count for `revoke`;
  - due grants and stale requests for `sweep`;
  - the files `keys init` would create (exit 1 if they already exist);
  - read-only warnings for `preflight`.

  `grant list`/`status` are read-only and never create state. `--dry-run` is kept as a no-op alias, and `--apply --dry-run` is a usage error (2).
- **Config:** `--dsn` or `$DATAGRANT_DSN` (admin), `--policy` or `$DATAGRANT_POLICY`, plus key and log paths from U3/U5 (`--signing-key`, `--receipt-log`). The DSN password is never printed. Errors are redacted (the DSN's own password, `password=…` and `user:pass@` forms).
- **Exit codes:** 0 ok, 1 denied/failed, 2 usage, 3 receipt not written (the access change still happened), 4 revoke failed (grant still active; the next sweep retries).
- **Identity:** the OS user (`getpass.getuser()`), or `--as-user` for automation and tests. **Neither is authentication.** Anyone who can run datagrant with the admin DSN can claim any name. Real separation of duties needs the admin DSN held by a trusted service or wrapper that authenticates people. Output says which source was used (`identity_source`).
- **`request`:** evaluates the policy (denied: reasons, exit 1). Without `--apply` it connects only to read the table catalog and prints the plan. With `--apply` it requires the signing key (no key, no grant).
  - **Auto mode:** applies the grant and prints connection info and the one-time password once, to stdout only. The password is not stored, logged, or put in receipts.
  - **Two-person mode:** stores a pending row in `datagrant.requests` (default TTL 24h, `--pending-ttl`) holding only the SCRAM verifier, and prints the request id plus the one-time password to the *requester*. The password works only after approval, and the approver never sees it.
- **`approve`:** loads the current policy and re-evaluates the stored request (a tightened policy refuses it). The approver must differ from the requester and be in a policy `approvers` group (a new top-level key, required for `two-person`). One transaction creates the role with the stored verifier and claims the request (`pending → approved`, only if not expired), so only one approval can win. The verifier is then cleared. The grant row and the `issued` receipt record `approvers: [approver]`.
- **`sweep`:** revokes expired grants (U4) and marks pending requests past their TTL `expired`, clearing their verifiers.
- **`revoke`/`sweep` without a signing key:** they still revoke and exit 3 (removing access never waits on a key).
