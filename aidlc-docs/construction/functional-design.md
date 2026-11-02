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
