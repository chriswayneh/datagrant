# Design: warehouses (v0.6.0 / M4)

Status: approved. Construction started (policy `engine`, routing, Snowflake grant engine, revoke and sweep). M4 design and execution plan (warehouses, target v0.6.0) from the v1.0 plan Chris authorized. M2 parked other warehouses at v0.5.0+ so they would not land in v0.4.0. M3 moved them to **v0.6.0+** so ops hardening could finish first. M3 is released. Chris approved the recommended picks and merged the design as PR #47 at `0449a0b`. Roadmap: [ROADMAP.md](../../ROADMAP.md).

Grounded in the v0.5.0 code on `main` (`src/datagrant/cli.py`, `policy.py`, `pg/grant.py`, `pg/revoke.py`, `pg/mask.py`, `receipt.py`, `docs/security.md`, `docs/policy.md`).

## Goal

v0.5.0 can issue, approve, receipt, revoke and doctor **Postgres** grants. The same request, mask, expire and receipt model is still Postgres-only. Teams that store PHI/PII in Snowflake or BigQuery cannot use datagrant there.

M4 adds **one other warehouse** so a developer can ask for columns and rows, get short masked access, and leave a signed receipt, without turning datagrant into a hosted service or a second product.

Out of scope for M4: a second warehouse in the same milestone (see [Which warehouse](#which-warehouse)), rate limits, `max_rows`, break-glass, a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, PyPI publish, native Snowflake masking policies as a second grant model, BigQuery IAM service-account-per-grant (if Snowflake is first), Snowflake PERSON users with passwords (MFA rollout; see [Login](#login)), and anything only a warehouse admin can bypass without a real enforcement point. Emergency access stays a reviewed policy edit to `approval: auto`.

## Which warehouse

Chris asked for Snowflake **and** BigQuery on the roadmap. Each one is a new SQL dialect, catalog, login model, revoke path, and test story.

**Verdict: Snowflake in M4 (v0.6.0). BigQuery later (v0.7.0+).** Snowflake has service users, roles, key-pair auth, and views that map to today's Postgres grant. BigQuery is IAM and authorized views; it does not issue a per-grant login. Doing both at once would swallow the milestone the same way putting warehouses in M3 would have swallowed ops hardening. Decision 1.

## What is already true (do not rebuild)

| Behavior | Where | Keep as-is |
| --- | --- | --- |
| Deny-by-default YAML policy; unknown keys are errors; `policy.version` is `1` | `policy.py` | New keys optional. Omitting them is v0.5.0 Postgres. |
| CLI dry run unless `--apply`; exit codes 0-4 | `cli.py` | Same commands. Snowflake `--apply` uses a Snowflake connection. |
| Local or OIDC identity on `request` / `approve` | `cli.py`, `oidc.py` | CLI identity stays a CLI boundary. The warehouse admin login is a service user with key-pair auth, like `DATAGRANT_DSN`. |
| Receipts version 1, local JSONL, optional sink | `receipt.py` | No new events required. Engine name and public-key fingerprint may be additive on `issued` facts. Never the private key. |
| Hash key and signing key files (0600, no symlinks) | `keys.py` | Same local files. The hash key is **not** copied into Snowflake view SQL (see [Hash key](#hash-key)). |
| Postgres grant: masked `security_barrier` view, LOGIN role, SCRAM, `VALID UNTIL` | `pg/grant.py` | Unchanged. M4 does not rewrite Postgres. |
| Postgres revoke: lock out, terminate sessions, drop | `pg/revoke.py` | Unchanged. |
| Postgres ops: advisory lock, doctor, `strict_preflight`, `SET LOCAL log_statement` | M3 | Postgres-only. Snowflake has no `log_statement` switch. Do not fake them. |
| `make demo` is local Postgres two-person | `scripts/demo.py` | Stay that way. |
| No break-glass, no rate limits, no `max_rows` | Chris | Still out. |

## Scope judgment

| Candidate | Verdict | Why |
| --- | --- | --- |
| Snowflake grant path (secure view, per-grant `TYPE=SERVICE` user, key pair shown once, revoke) | **Keep** (recommended) | Closest match to today's Postgres grant after Snowflake's MFA rollout. Decision 1, 3. |
| BigQuery in M4 | **Cut** (v0.7.0+) | Different identity (IAM, no per-grant login). Decision 1. |
| Core CLI path: `request`, `approve`, `revoke`, `sweep`, `grant list/status`, receipts, `policy check` | **Keep** | That is the product. Decision 2. |
| Port doctor, advisory lock, PUBLIC preflight, `SET log_statement` to Snowflake | **Cut** | Those close Postgres host gaps. Concurrent sweep vs issue is a `datagrant.grants` row with status `issuing` plus a 10-minute grace, not a Snowflake lock. |
| Per-grant `TYPE=SERVICE` user with a key pair generated locally | **Keep** (recommended) | PERSON password sign-in requires MFA; SERVICE users cannot use passwords. Decision 3. |
| Per-grant PERSON user with a one-time password | **Cut** | Broken by the Aug-Oct 2026 MFA rollout. |
| Reuse one Snowflake user and swap views | **Cut** | Shared login is standing access. |
| Grantee logs in with company Snowflake SSO | **Cut** for M4 | Mixes datagrant with the company's IdP in one step. OIDC stays on the CLI. Decision 3. |
| Optional `engine` on each dataset (`postgres` default) | **Keep** (recommended) | One policy can list Postgres and Snowflake datasets later. Omit = Postgres. Decision 4. |
| One engine per policy file | **Cut** (recommended) | Breaks mixed estates and is unnecessary if omit means Postgres. |
| Masked **views** (same five mask names) | **Keep** (recommended) | One receipt and one revoke path. Decision 7. |
| Native Snowflake masking policies as the grant | **Cut** | Second model, different revoke, different evidence. |
| Hash key inlined in view SQL (`SHA2_HMAC(..., '<key>', ...)`) | **Cut** | Lands in view DDL and `QUERY_HISTORY`. No `log_statement` switch. See [Hash key](#hash-key). |
| Hash key in a restricted table plus a SQL secure UDF (admin-owned; `USAGE` on the UDF only) | **Keep** (recommended) | View text calls the UDF; grant roles never `SELECT` the table. SQL UDFs cannot read secrets. See [Hash key](#hash-key). |
| Hash key in a Snowflake SECRET | **Optional** | Needs a Python, Java, or Scala UDF with an `EXTERNAL_ACCESS_INTEGRATION` that allows the secret, plus `READ` on the secret. Not the default. |
| Optional extra `datagrant[snowflake]` | **Keep** | Postgres-only installs do not pull a Snowflake driver. |
| Live Snowflake in GitHub Actions | **Cut** | Needs an account and secrets. Decision 5. |
| Recorded-SQL unit tests; live tests behind `DATAGRANT_TEST_SNOWFLAKE_DSN` | **Keep** (recommended) | CI stays green without Snowflake. Decision 5. |
| Change `make demo` to Snowflake | **Cut** | The GIF and CI demo stay Postgres. Decision 6. |
| Second `make demo-snowflake` in M4 CI | **Cut** | No Snowflake in CI. A docs walkthrough can wait for a live extra. |
| Rate limits, `max_rows`, break-glass, PyPI, hosted service | **Cut** | Chris. Same as M2/M3. |
| `policy.version` bump | **Cut** | Omit new keys = v0.5.0. |

## Operator configuration

`policy.version` stays `1`. Unknown keys remain errors. New keys are optional.

```yaml
version: 1
approval: two-person
approvers: [sec]
max_duration: 8h
groups:
  ml: [alice]
  sec: [carol]
datasets:
  - name: clinic
    database: clinicdb          # Postgres (omit engine)
    tables:
      - name: public.patients
        allowed_groups: [ml]
        columns: {patient_id: passthrough, ssn: hash}
  - name: snow_clinic
    engine: snowflake           # optional; omit = postgres
    database: CLINIC_DB         # Snowflake database
    schema: PUBLIC              # optional Snowflake schema default for tables
    tables:
      - name: PUBLIC.PATIENTS
        allowed_groups: [ml]
        columns: {PATIENT_ID: passthrough, SSN: hash}
```

Validation (`datagrant policy check` enforces this offline):

- `engine`: `postgres` (default, including omitted) or `snowflake`. Unknown strings are errors. A table-level `engine` is an unknown-key error.
- Snowflake datasets still use `database` (Snowflake database name). Optional dataset `schema` is a default schema for table names that omit one. Table `name` stays `schema.table`.
- Omitting `engine` on every dataset is v0.5.0.
- `DATAGRANT_DSN` stays the Postgres admin URL. Snowflake uses `DATAGRANT_SNOWFLAKE_DSN` / `--snowflake-dsn`. The operator login must be a **service user with key-pair auth** via `private_key_file` (PERSON password sign-in needs MFA; SERVICE users cannot use passwords). A password in the DSN is refused. `connect()` requires `private_key_file`. A Snowflake `--apply` without that config is exit 2. Postgres `--apply` does not read the Snowflake settings.
- `hash`, `redact`, `partial`, `null`, `passthrough` keep the same names. Snowflake `hash` is HMAC-SHA256 via the hash UDF (see [Hash key](#hash-key)). Hashes are **not** joinable with Postgres hashes of the same value. Use separate `hash_scope` values.

No other policy keys in M4. Rate limits and `max_rows` are not added.

## Login

Snowflake's 2026 MFA rollout (documented Aug-Oct 2026): **PERSON** users must use MFA to sign in with a password. **SERVICE** users cannot use passwords. A Postgres-style one-time password therefore does not work for a per-grant login.

M4 uses a **per-grant `TYPE=SERVICE` user** and **key-pair auth**:

1. datagrant generates an RSA key pair locally (never sent as a private key to Snowflake).
2. `CREATE USER ... TYPE = SERVICE RSA_PUBLIC_KEY = '<public>'` (public key only in SQL).
3. The **private key** is shown once to the requester (stdout), or written to a caller-chosen `0600` regular file (same bar as `--oidc-token-file`). It is not stored in state, receipts, logs, or Snowflake.
4. The `issued` receipt records only a **public-key fingerprint** (`sha256` of the DER public key), never the private key and never the public PEM.
5. Two-person: generate at `request`, show the private key to the requester then, and store only the public key plus fingerprint in the pending row. Do **not** create a Snowflake user, view, or role at request. The final `approve` runs the fail-safe sequence (`issuing` row, DISABLED user, view, role, state, issued receipt, ENABLE, then `active`). Pending rows past `pending_ttl` expire in place; there is nothing in Snowflake to drop.

Decision 3.

## CLI and grant model (Snowflake)

**Connect.** `approve` / `revoke` / `sweep` / `grant list` for a Snowflake dataset open a Snowflake session as the operator's **service user** (key pair via `private_key_file`, never logged). Password auth is not supported on the operator DSN. Two-person `request --apply` may inspect the catalog; it creates no Snowflake user, view, or role. Dry runs do not connect unless they already do for Postgres catalog checks; Snowflake dry run prints the SQL plan the same way. Snowflake `--apply` for grant issue and approve stays refused until a follow-up PR after revoke/sweep.

**When this sequence runs.** `approval: auto` `--apply`, and the final two-person `approve --apply`. Not at two-person `request`.

**Snowflake DDL auto-commits.** There is no single warehouse transaction that can roll back `CREATE USER` / `CREATE VIEW`. Grant state is **one store**: `datagrant.grants` in Snowflake. Fail-safe order (each step its own statement):

1. Insert into `datagrant.grants` with `status = 'issuing'` and `started_at` (now). That DML autocommits before any `CREATE USER`. Any host's sweep can see the in-flight grant.
2. Create the `TYPE=SERVICE` user **DISABLED**, `RSA_PUBLIC_KEY` set, comment/tag `datagrant:<grant_id>` (cannot log in).
3. Create the **secure view** in a datagrant-owned schema (mask expressions call the hash UDF; see [Hash key](#hash-key)).
4. Create the **role**, `GRANT SELECT` on that view only, `GRANT` the role to the user, and `GRANT USAGE` on the database, the view schema, and the warehouse (so the view is queryable). Do **not** `GRANT USAGE` on the hash UDF: a Snowflake secure view runs as the owner, so the grant role never calls `HASH_HMAC` itself.
5. Update that same `datagrant.grants` row as needed (view/role names, public-key fingerprint). Status stays `issuing`.
6. Write the `issued` receipt. If the receipt cannot be written: drop in reverse order while the user is still DISABLED (no login was possible). Set the `datagrant.grants` row to `failed` and write a failure receipt. No `issued` receipt, no access.
7. Claim `issuing` to `enabling` (`UPDATE ... SET STATUS = ? WHERE ID = ? AND STATUS = ?`, rowcount must be 1). If 0 rows (revoke or sweep already took the row), reverse-drop while DISABLED and raise. Do not ENABLE.
8. **ENABLE the user last, only after the receipt is written and the enabling claim succeeded.**
9. Flip the `datagrant.grants` row to `active` only from `enabling` (`WHERE ID = ? AND STATUS = ?`, rowcount must be 1). If ENABLE fails, or the active claim is 0 rows: DISABLE, drop in reverse order, set the row to `failed`, and write a `revoked` receipt so a revoked grant cannot be brought back to `active`.

On **any failure** after step 2: drop what was created, **in reverse order** (the user is still DISABLED unless step 8 succeeded; if ENABLE already ran, DISABLE first). Do not ENABLE a user without a receipt. Do not leave `status = 'active'` unless ENABLE succeeded and the row was still `enabling`. If step 1 succeeded and later steps fail, set the `datagrant.grants` row to `failed`.

**Sweep garbage.** Sweep reads `datagrant.grants` in Snowflake. It skips any tagged user whose row is `issuing` or `enabling` and whose `started_at` is younger than **10 minutes**. After that grace period, an `issuing` or `enabling` row is treated as crashed: drop the tagged user, role, and view, set the row to `failed`, and write a failure receipt. Other tagged `DISABLED` users with no matching `active` row (and no in-grace `issuing`/`enabling` row) are leftover and dropped. Two-person pending requests are not Snowflake users, so this rule does not touch them. A pending row past `pending_ttl` is marked expired (same as Postgres); there is nothing in Snowflake to drop.

**Revoke / sweep of a live grant.** DISABLE the user first (so new logins fail), cancel running queries for that user, drop the view and role, mark state revoked or expired. Access removal must not fail open on a missing receipt (exit 3 after DISABLE, same as Postgres).

**Expiry under a day.** Snowflake `DAYS_TO_EXPIRY` is **day-granular**; it cannot end a 2h grant at two hours. Sub-day expiry is enforced by **sweep cadence**. Optionally also set `DAYS_TO_EXPIRY` to 1 (a calendar-day backstop) and/or a Snowflake task that runs the same disable/drop. **Recommend: run `datagrant sweep --apply` every 1 minute** via cron or systemd, same as Postgres (`* * * * *`). Worst case if a sweep is missed: the grant user stays ENABLE until the next successful sweep. If sweep is down for N minutes, that is N minutes of extra live access. If sweep is down past `DAYS_TO_EXPIRY` (1 day for sub-day grants), Snowflake disables the user as a backstop. Do not advertise `DAYS_TO_EXPIRY` as a substitute for sweep.

**Catalog.** Column types come from the Snowflake information schema at grant time, the same idea as `inspect_table` today.

**Masks (Snowflake SQL, same names):**

| Mask | Grantee sees |
| --- | --- |
| `passthrough` | The real value. |
| `redact` | The constant `[REDACTED]`. |
| `null` | NULL, cast to the column type. |
| `partial` | Asterisks plus the last 4 characters; values shorter than 8 characters fully masked. |
| `hash` | Hex HMAC-SHA256 from the hash UDF (key not in the view text). |

**Not in M4.** `datagrant doctor` Snowflake checks, Snowflake warehouse locks (the `datagrant.grants` `issuing` row plus a 10-minute grace is the race control, not a Snowflake lock), Snowflake `log_statement`, network policies, Snowflake masking policies, sharing a warehouse user, PERSON password grants, BigQuery.

Exit codes stay 0-4. A missing Snowflake driver (`pip install datagrant[snowflake]`) is exit 2 on a Snowflake `--apply`, with a message that names the extra.

## Hash key

The local hash key file stays as today. It must **not** appear in view SQL. Snowflake has no session `log_statement = none` switch; view DDL and `QUERY_HISTORY` keep statement text.

**Default:** a **restricted table** (`datagrant._hash_master`) holding the hash key, filled with a **bind parameter** (never a SQL literal), plus a **SQL secure UDF** (`datagrant.hash_hmac(hash_scope, value)`) owned by the admin role. The UDF reads the table and derives the per-scope HMAC key (same idea as Postgres). Views call the UDF. The grant role does not get `USAGE` on the UDF (the secure view runs as the owner) and never gets `SELECT` on the table. Grant the role `USAGE` on the database, the view schema, and the warehouse so it can query the view. SQL UDFs cannot read Snowflake secrets.

**Optional SECRET path:** a Python, Java, or Scala UDF with an `EXTERNAL_ACCESS_INTEGRATION` that allows the secret, plus `READ` on the secret. Not the M4 default. SQL UDFs cannot use this path.

Invariant: **key never in view text, never in `CREATE USER` text.**

## Threat and ops notes

- **Admin credentials still bypass the CLI.** Anyone who can create users and views in the Snowflake account can read the data directly. Run datagrant on a bastion that holds `DATAGRANT_SNOWFLAKE_DSN`, same as Postgres.
- **OIDC is still a CLI boundary.** It names the requester. It does not log the developer into Snowflake.
- **A Snowflake service user is a login.** Treat it like the Postgres grant role: short, unique, dropped on revoke. Do not reuse it. PERSON password grants are out (MFA).
- **Private key is shown once.** Same handling as the Postgres one-time password: stdout or a `0600` file, never receipts, never logs, never Snowflake SQL. Receipts store only the public-key fingerprint.
- **`CREATE USER` SQL contains the public key only.** No private key, no hash key, no password.
- **View DDL and `QUERY_HISTORY`.** Anyone who can `GET_DDL` on the view or read `QUERY_HISTORY` / `ACCOUNT_USAGE.QUERY_HISTORY` sees the view text (UDF name, column list, filter). They must not see the HMAC key. Restrict `ACCOUNT_USAGE` to operators. Retention is account-configured (often long); assume history outlives the grant.
- **Restricted-table residual.** A bind avoids putting the key in the SQL string datagrant sends. Snowflake may still retain statement text or bind values in `ACCOUNT_USAGE` depending on account settings. Operators who can `SELECT` the master table can recompute hashes. Grant roles must not have `SELECT` on that table and do not need `USAGE` on the UDF (the secure view runs as owner). The optional SECRET path adds `READ` on the secret plus an `EXTERNAL_ACCESS_INTEGRATION`; SQL UDFs cannot read secrets.
- **Secure views hide the view SQL from the grantee.** They do not hide that every visible row matched the filter. Same limit as Postgres.
- **Hashes do not match Postgres.** Do not join a Snowflake `hash` column to a Postgres `hash` column.
- **DDL auto-commit.** A crash can leave a `DISABLED` tagged user. Sweep drops it only after the `issuing`/`enabling` grace (10 minutes). ENABLE runs only after view, role, the `datagrant.grants` row, the `issued` receipt, and an `issuing` to `enabling` claim. The `datagrant.grants` row becomes `active` only from `enabling` after ENABLE succeeds.
- **No Snowflake in CI.** A missing `DATAGRANT_TEST_SNOWFLAKE_DSN` skips live tests. Recorded SQL still runs.
- **`make demo` stays Postgres.** Operators try Snowflake against a throwaway database they already have, after `policy check`.
- **DSN holders and warehouse admins are trusted.** Same as today.

## Known limits

- **Sub-day expiry is sweep, not `DAYS_TO_EXPIRY`.** Snowflake `DAYS_TO_EXPIRY` is day-granular, so it cannot end a 2h grant at two hours. Run `datagrant sweep --apply` every 1 minute (`* * * * *`). Optional: `DAYS_TO_EXPIRY = 1` and/or a Snowflake task as a calendar-day backstop, not as the primary timer.
- **Missed-sweep live window.** If a sweep is missed, the grant user stays ENABLE until the next successful sweep. Down for N minutes means about N minutes of extra live access. If sweep stays down past `DAYS_TO_EXPIRY` (1 day for sub-day grants), that backstop disables the user. Worst case with no sweep and no backstop: the grant stays live until someone runs sweep or revoke.
- **`issuing`/`enabling` grace is 10 minutes.** Sweep will not drop a tagged user whose `datagrant.grants` row is `issuing` or `enabling` and younger than 10 minutes. A live issue that runs longer than 10 minutes can be cleaned up as crashed. A crashed issue younger than 10 minutes keeps DISABLED objects until the grace ends. Sweep reads `datagrant.grants` in Snowflake, so any host sees in-flight grants. This is not a Snowflake lock.

## Compatibility with v0.5.0

- Policies that omit `engine` parse and evaluate as today. `policy.version` stays `1`.
- Receipt JSONL from v0.5.0 remains valid input to `receipts verify`. Additive fingerprint fields on new Snowflake `issued` rows must not break verify of old lines.
- `make demo`, doctor, advisory lock, and `SET LOCAL log_statement` are unchanged (Postgres).
- Existing keys, Postgres DSNs, and runbooks keep working.
- Installing without `[snowflake]` keeps today's Postgres CLI. Snowflake `--apply` tells the operator to install the extra.

## Test plan (each construction PR)

- Policy: omit `engine` = postgres; `engine: snowflake` accepted; unknown engine is a parse error; table-level `engine` is an unknown-key error; `policy check` covers a mixed file.
- Routing: a postgres dataset never opens Snowflake; a snowflake dataset `--apply` without Snowflake config is exit 2; missing extra names `datagrant[snowflake]`.
- Grant SQL (unit, no network): plan inserts an `issuing` row (`started_at`) into `datagrant.grants` **before** `CREATE USER`, then DISABLED user, view, role, updates that same row as needed, **receipt, claim issuing to enabling, ENABLE last**, then flips the row to `active` only from `enabling`. A stub receipt failure must not ENABLE. A stub that flips the row away from `issuing` before ENABLE must not ENABLE. A stub that flips away from `enabling` before `active` must DISABLE, drop, and write `revoked`. A stub ENABLE failure after the `issued` receipt writes a `revoked` or `failed` receipt and does not leave `active`. `CREATE USER` SQL contains `RSA_PUBLIC_KEY` and no private key, no password, no hash key. View SQL calls `datagrant.hash_hmac` (SQL secure UDF) and does not contain hash-key bytes. Grant role SQL has `USAGE` on the database, view schema, and warehouse, no `USAGE` on the hash UDF, and no `SELECT` on `datagrant._hash_master`. Dry run prints the plan and creates nothing. Receipt payload has a fingerprint field and not a private key. Snowflake `--apply` for grant issue and approve stays refused (exit 2) after revoke/sweep; re-enable in a follow-up PR. Dry-run plans still print.
- Two-person pending (unit): a pending request stores public key plus fingerprint only, survives sweep, and creates nothing in Snowflake until the final approve. A pending row past `pending_ttl` expires with no Snowflake drop.
- Fail-safe (unit): a stub failure after CREATE USER still leaves the user DISABLED; reverse-drop is issued. Sweep during an in-flight issue (`datagrant.grants` row `issuing` or `enabling`, under the 10-minute grace) drops nothing. An `issuing` or `enabling` row older than grace is cleaned up (objects dropped, row `failed`, failure receipt). Sweep does not drop pending two-person requests.
- Revoke SQL (unit): DISABLE first, cancel queries, drop view and role. Sweep expires by `expires_at`. Receipt failure after DISABLE is exit 3.
- Expiry docs/tests: `DAYS_TO_EXPIRY` is not treated as sub-day enforcement; sweep cadence is.
- Compat: existing Postgres unit and integration tests still pass without a Snowflake extra.
- Extra pin: `snowflake-connector-python>=4.7.3,<6` (not `>=3.12,<4`, which resolved 3.18.1 / PYSEC-2026-4301). CI job `pip-audit-snowflake` installs `.[snowflake]` and runs `pip-audit`. No live Snowflake calls.
- Live (optional): if `DATAGRANT_TEST_SNOWFLAKE_DSN` is set, issue, SELECT through the grant service user with the shown key pair, revoke, confirm the user cannot log in. GET_DDL / query-history checks on a throwaway account must not show the hash key. Fictional data only. CI default is unset (skip).
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as M3: one concern per PR, tests in each, docs last. No BigQuery PR. No rate-limit PR. No `max_rows` PR. No break-glass PR.

1. **Done (PR #47).** Design, ROADMAP, audit pointer. No runtime.
2. **Done (PR #48).** Policy `engine` and connection routing. Parse `engine` (`postgres` default, `snowflake` allowed). Snowflake `--apply` requires Snowflake config and the optional extra.
3. **Done (PR #49).** Snowflake grant engine. Insert `issuing` into `datagrant.grants` before CREATE USER, secure view, role, per-grant `TYPE=SERVICE` user (DISABLED, receipt, ENABLE, then `active` on that same row), key pair shown once, restricted hash table plus SQL secure UDF (secure view runs as owner; grant role gets database/schema/warehouse `USAGE`, not UDF `USAGE`), `issued` receipt with public-key fingerprint. Two-person request stores public key plus fingerprint only; objects are created at final approve. Dry run. Tests on the SQL plan and reverse-drop.
4. **This PR.** Snowflake revoke and sweep. DISABLE, cancel queries, drop, fail-safe receipts, skip `datagrant.grants` `issuing` and `enabling` rows under the 10-minute grace, garbage-collect tagged DISABLED users and expired `issuing`/`enabling` rows. Pending TTL expiry does not drop Snowflake objects. `grant list` / `status` for Snowflake rows. `claim_pending` before `apply_plan` and `mark_request_failed` on apply failure. Issue claims `issuing` to `enabling` before ENABLE and `enabling` to `active` after; 0-row claims reverse-drop so a revoked grant cannot return to `active`. Operator DSN is key-pair only (`private_key_file`; password not supported). Snowflake `--apply` for grant issue and approve stays refused.
5. **Re-enable Snowflake `--apply`.** Small follow-up after revoke/sweep: turn on grant issue and approve `--apply` (`GRANT_APPLY_ENABLED`).
6. **Snowflake masks and catalog.** Five mask names, type inspect, row filters re-emitted safely. Hash-scope documented as not joinable with Postgres. Assert view DDL has no key bytes.
7. **Docs, runbook, CHANGELOG Unreleased, v0.6.0 prep (no tag).** Sweep every 1 minute. `docs/cli.md`, `docs/policy.md`, `docs/security.md`, this design marked implemented.

## Decisions for Chris

Chris approved all recommended picks on 2026-11-12 CT (PR #47 merged at `0449a0b`): **1B, 2B, 3A, 4A, 5B, 6B, 7B**. The one-line why is the whole point.

1. **Which warehouse do we build in this version?**
   - A. Snowflake and BigQuery both.
   - B. Snowflake now; BigQuery in a later version.
   - C. BigQuery now; Snowflake later.
   - **Recommend B (approved).** Snowflake has logins and views like Postgres; doing both at once would stall the release.

2. **How much of today's Postgres product should Snowflake copy?**
   - A. Everything, including doctor, the writer lock, and statement-logging tricks.
   - B. The path people use: ask, approve, masked access, expiry, receipt, revoke.
   - C. Masked views only, no receipts.
   - **Recommend B (approved).** That is what datagrant is for; the Postgres host checks do not translate.

3. **How does the developer sign in to Snowflake?**
   - A. A per-grant service user with a key pair that datagrant shows once (or writes to a private file).
   - B. A per-grant user with an OAuth / programmatic access token.
   - C. The developer's existing company Snowflake SSO (later).
   - **Recommend A (approved).** Snowflake now requires MFA for password logins and forbids passwords on service users; a one-time key pair is the closest thing to today's one-time password.

4. **Can one policy file list both Postgres and Snowflake tables?**
   - A. Yes. Each dataset can say `engine: snowflake`. If it says nothing, it stays Postgres.
   - B. No. One policy file is one engine.
   - C. A separate Snowflake-only tool and config file.
   - **Recommend A (approved).** Current files keep working; mixed teams do not need two tools.

5. **How do we test this without a Snowflake bill in GitHub Actions?**
   - A. Require a real Snowflake account in CI.
   - B. Check the SQL in tests; run live tests only when someone sets a secret.
   - C. No Snowflake tests.
   - **Recommend B (approved).** CI stays free and green; people with Snowflake can still prove it live.

6. **Does the one-command demo need Snowflake?**
   - A. Replace today's Postgres demo.
   - B. Keep the Postgres demo; Snowflake is docs and tests.
   - C. Add a second demo that needs a Snowflake account, and run it in CI.
   - **Recommend B (approved).** The public demo and CI stay as they are.

7. **Snowflake's own masking policies, or datagrant views like Postgres?**
   - A. Use Snowflake masking policies as the grant.
   - B. Keep datagrant masked views (same five names as Postgres).
   - C. Support both in this version.
   - **Recommend B (approved).** One way to grant, one way to revoke, one receipt.

## Decisions already on record (Chris)

1. **Warehouses were not M2.** Originally "v0.5.0+". M3 moved them to **v0.6.0+**. This design is that milestone.
2. **Rate limits stay out.**
3. **`max_rows` stays out.**
4. **No break-glass.** Emergency path is a reviewed policy edit to `approval: auto`.
5. **M3 was ops hardening, not a second engine.** Released as v0.5.0.
