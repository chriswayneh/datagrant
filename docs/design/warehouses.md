# Design: warehouses (v0.6.0 / M4)

Status: proposed. Not implemented. This is the M4 design and execution plan (warehouses, target v0.6.0) from the v1.0 plan Chris authorized. M2 parked other warehouses at v0.5.0+ so they would not land in v0.4.0. M3 moved them to **v0.6.0+** so ops hardening could finish first. M3 is released. This milestone is that warehouse work. Construction must not start until this document is approved in [audit.md](../../aidlc-docs/audit.md). Roadmap: [ROADMAP.md](../../ROADMAP.md).

Grounded in the v0.5.0 code on `main` (`src/datagrant/cli.py`, `policy.py`, `pg/grant.py`, `pg/revoke.py`, `pg/mask.py`, `receipt.py`, `docs/security.md`, `docs/policy.md`).

## Goal

v0.5.0 can issue, approve, receipt, revoke and doctor **Postgres** grants. The same request, mask, expire and receipt model is still Postgres-only. Teams that store PHI/PII in Snowflake or BigQuery cannot use datagrant there.

M4 adds **one other warehouse** so a developer can ask for columns and rows, get a short masked login, and leave a signed receipt, without turning datagrant into a hosted service or a second product.

Out of scope for M4: a second warehouse in the same milestone (see [Which warehouse](#which-warehouse)), rate limits, `max_rows`, break-glass, a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, PyPI publish, native Snowflake masking policies as a second grant model, BigQuery IAM service-account-per-grant (if Snowflake is first), and anything only a warehouse admin can bypass without a real enforcement point. Emergency access stays a reviewed policy edit to `approval: auto`.

## Which warehouse

Chris asked for Snowflake **and** BigQuery on the roadmap. Each one is a new SQL dialect, catalog, login model, revoke path, and test story.

**Verdict: Snowflake in M4 (v0.6.0). BigQuery later (v0.7.0+).** Snowflake has users, roles, passwords, views, and an expiry-style disable that maps to today's Postgres grant. BigQuery is IAM and authorized views; it does not print a one-time password. Doing both at once would swallow the milestone the same way putting warehouses in M3 would have swallowed ops hardening. Decision 1.

## What is already true (do not rebuild)

| Behavior | Where | Keep as-is |
| --- | --- | --- |
| Deny-by-default YAML policy; unknown keys are errors; `policy.version` is `1` | `policy.py` | New keys optional. Omitting them is v0.5.0 Postgres. |
| CLI dry run unless `--apply`; exit codes 0-4 | `cli.py` | Same commands. Snowflake `--apply` uses a Snowflake connection. |
| Local or OIDC identity on `request` / `approve` | `cli.py`, `oidc.py` | CLI identity stays a CLI boundary. The warehouse admin login is a service account, like `DATAGRANT_DSN`. |
| Receipts version 1, local JSONL, optional sink | `receipt.py` | No new events required. Engine name may be additive on `issued` facts. |
| Hash key and signing key files (0600, no symlinks) | `keys.py` | Same files. Snowflake HMAC uses the same hash key. |
| Postgres grant: masked `security_barrier` view, LOGIN role, SCRAM, `VALID UNTIL` | `pg/grant.py` | Unchanged. M4 does not rewrite Postgres. |
| Postgres revoke: lock out, terminate sessions, drop | `pg/revoke.py` | Unchanged. |
| Postgres ops: advisory lock, doctor, `strict_preflight`, `SET LOCAL log_statement` | M3 | Postgres-only. Do not fake them on Snowflake. |
| `make demo` is local Postgres two-person | `scripts/demo.py` | Stay that way. |
| No break-glass, no rate limits, no `max_rows` | Chris | Still out. |

## Scope judgment

| Candidate | Verdict | Why |
| --- | --- | --- |
| Snowflake grant path (secure view, per-grant user, one-time password, revoke) | **Keep** (recommended) | Closest match to today's Postgres grant. Decision 1. |
| BigQuery in M4 | **Cut** (v0.7.0+) | Different identity (IAM, no password user). Decision 1. |
| Core CLI path: `request`, `approve`, `revoke`, `sweep`, `grant list/status`, receipts, `policy check` | **Keep** | That is the product. Decision 2. |
| Port doctor, advisory lock, PUBLIC preflight, `SET log_statement` to Snowflake | **Cut** | Those close Postgres host gaps. Snowflake has different admin mistakes. |
| Per-grant Snowflake user with a one-time password | **Keep** (recommended) | Same story as Postgres: password shown once, not stored. Decision 3. |
| Reuse one Snowflake user and swap views | **Cut** | Shared login is standing access. |
| Grantee logs in with company Snowflake SSO | **Cut** for M4 | Mixes datagrant with the company's IdP in one step. OIDC stays on the CLI. Decision 3. |
| Optional `engine` on each dataset (`postgres` default) | **Keep** (recommended) | One policy can list Postgres and Snowflake datasets later. Omit = Postgres. Decision 4. |
| One engine per policy file | **Cut** (recommended) | Breaks mixed estates and is unnecessary if omit means Postgres. |
| Masked **views** (same five mask names) | **Keep** (recommended) | One receipt and one revoke path. Decision 7. |
| Native Snowflake masking policies as the grant | **Cut** | Second model, different revoke, different evidence. |
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
- `DATAGRANT_DSN` stays the Postgres admin URL. Snowflake uses `DATAGRANT_SNOWFLAKE_DSN` (or equivalent documented account/user/role/warehouse settings). A Snowflake `--apply` without that config is exit 2. Postgres `--apply` does not read the Snowflake settings.
- `hash`, `redact`, `partial`, `null`, `passthrough` keep the same names. Snowflake `hash` is HMAC-SHA256 with the local hash key and `hash_scope`. Hashes are **not** joinable with Postgres hashes of the same value (different SQL, different encoding). Use separate `hash_scope` values.

No other policy keys in M4. Rate limits and `max_rows` are not added.

## CLI and grant model (Snowflake)

**Connect.** `request` / `approve` / `revoke` / `sweep` / `grant list` for a Snowflake dataset open a Snowflake session as the operator's admin (key pair or password, never logged). Dry runs do not connect unless they already do for Postgres catalog checks; Snowflake dry run prints the SQL plan the same way.

**Issue (`--apply`).** In one warehouse transaction (fail closed):

1. Create a **secure view** in a datagrant-owned schema with the requested columns, mask expressions, and the allow-listed row filter.
2. Create a **role** that can `SELECT` only that view.
3. Create a **user** with a one-time password, default role that grant role, and a time bound (disable-at / days-to-expiry as Snowflake allows). Print the password once. Do not store it. Do not send the plaintext in SQL if the driver can bind it.
4. Write `datagrant.grants` state in Snowflake (same facts as Postgres: id, requester, dataset, table, expires_at, status).
5. Write the local `issued` receipt. No receipt, no access: disable and drop on a failed write.

**Revoke / sweep.** Disable the user first (so new logins fail), cancel running queries for that user, drop the view and role, mark state revoked or expired. Access removal must not fail open on a missing receipt (exit 3 after disable, same as Postgres).

**Catalog.** Column types come from the Snowflake information schema at grant time, the same idea as `inspect_table` today.

**Masks (Snowflake SQL, same names):**

| Mask | Grantee sees |
| --- | --- |
| `passthrough` | The real value. |
| `redact` | The constant `[REDACTED]`. |
| `null` | NULL, cast to the column type. |
| `partial` | Asterisks plus the last 4 characters; values shorter than 8 characters fully masked. |
| `hash` | Hex HMAC-SHA256 under the local hash key and `hash_scope`. |

**Not in M4.** `datagrant doctor` Snowflake checks, Snowflake locks, Snowflake `log_statement`, network policies, Snowflake masking policies, sharing a warehouse user, BigQuery.

Exit codes stay 0-4. A missing Snowflake driver (`pip install datagrant[snowflake]`) is exit 2 on a Snowflake `--apply`, with a message that names the extra.

## Threat and ops notes

- **Admin credentials still bypass the CLI.** Anyone who can create users and views in the Snowflake account can read the data directly. Run datagrant on a bastion that holds `DATAGRANT_SNOWFLAKE_DSN`, same as Postgres.
- **OIDC is still a CLI boundary.** It names the requester. It does not log the developer into Snowflake.
- **A Snowflake user is a login.** Treat it like the Postgres grant role: short, unique, dropped on revoke. Do not reuse it.
- **Secure views hide the view SQL from the grantee.** They do not hide that every visible row matched the filter. Same limit as Postgres.
- **Hashes do not match Postgres.** Do not join a Snowflake `hash` column to a Postgres `hash` column.
- **No Snowflake in CI.** A missing `DATAGRANT_TEST_SNOWFLAKE_DSN` skips live tests. Recorded SQL still runs.
- **`make demo` stays Postgres.** Operators try Snowflake against a throwaway database they already have, after `policy check`.
- **DSN holders and warehouse admins are trusted.** Same as today.

## Compatibility with v0.5.0

- Policies that omit `engine` parse and evaluate as today. `policy.version` stays `1`.
- Receipt JSONL from v0.5.0 remains valid input to `receipts verify`.
- `make demo`, doctor, advisory lock, and `SET LOCAL log_statement` are unchanged.
- Existing keys, Postgres DSNs, and runbooks keep working.
- Installing without `[snowflake]` keeps today's Postgres CLI. Snowflake `--apply` tells the operator to install the extra.

## Test plan (each construction PR)

- Policy: omit `engine` = postgres; `engine: snowflake` accepted; unknown engine is a parse error; table-level `engine` is an unknown-key error; `policy check` covers a mixed file.
- Routing: a postgres dataset never opens Snowflake; a snowflake dataset `--apply` without Snowflake config is exit 2; missing extra names `datagrant[snowflake]`.
- Grant SQL (unit, no network): plan includes a secure view, a role limited to that view, a user with a bound expiry, and no plaintext password in the SQL text if the driver can bind it. Mask SQL for all five names. Dry run prints the plan and creates nothing.
- Revoke SQL (unit): disable user, cancel queries, drop view and role. Sweep expires by `expires_at`. Receipt failure after disable is exit 3.
- Compat: existing Postgres unit and integration tests still pass without a Snowflake extra.
- Live (optional): if `DATAGRANT_TEST_SNOWFLAKE_DSN` is set, issue, SELECT through the grant user, revoke, confirm the user cannot log in. Fictional data only. CI default is unset (skip).
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as M3: one concern per PR, tests in each, docs last. No BigQuery PR. No rate-limit PR. No `max_rows` PR. No break-glass PR.

1. **This PR.** Design, ROADMAP, audit pointer. No runtime.
2. **Policy `engine` and connection routing.** Parse `engine` (`postgres` default, `snowflake` allowed). Snowflake `--apply` requires Snowflake config and the optional extra. No grant SQL yet.
3. **Snowflake grant engine.** Secure view, role, per-grant user, one-time password, state row, `issued` receipt. Dry run. Tests on the SQL plan.
4. **Snowflake revoke and sweep.** Disable, cancel queries, drop, fail-safe receipts. `grant list` / `status` for Snowflake rows.
5. **Snowflake masks and catalog.** Five mask names, type inspect, row filters re-emitted safely. Hash-scope documented as not joinable with Postgres.
6. **Docs, runbook, CHANGELOG Unreleased, v0.6.0 prep (no tag).** `docs/cli.md`, `docs/policy.md`, `docs/security.md`, this design marked implemented.

## Decisions for Chris

Each item needs Chris's call before construction. Recommended picks are the proposed default if the design is approved as-is. They are not yet approved. Chris is not expected to read the SQL; the one-line why is the whole point.

1. **Which warehouse do we build in this version?**
   - A. Snowflake and BigQuery both.
   - B. Snowflake now; BigQuery in a later version.
   - C. BigQuery now; Snowflake later.
   - **Recommend B.** Snowflake has logins and views like Postgres; doing both at once would stall the release.

2. **How much of today's Postgres product should Snowflake copy?**
   - A. Everything, including doctor, the writer lock, and statement-logging tricks.
   - B. The path people use: ask, approve, masked login, expiry, receipt, revoke.
   - C. Masked views only, no receipts.
   - **Recommend B.** That is what datagrant is for; the Postgres host checks do not translate.

3. **How does the developer log in to Snowflake?**
   - A. A new Snowflake user with a one-time password (like Postgres today).
   - B. One shared Snowflake user, with views swapped underneath.
   - C. The developer's existing company Snowflake SSO login.
   - **Recommend A.** Same habit as today; a shared user is standing access; SSO is a later project.

4. **Can one policy file list both Postgres and Snowflake tables?**
   - A. Yes. Each dataset can say `engine: snowflake`. If it says nothing, it stays Postgres.
   - B. No. One policy file is one engine.
   - C. A separate Snowflake-only tool and config file.
   - **Recommend A.** Current files keep working; mixed teams do not need two tools.

5. **How do we test this without a Snowflake bill in GitHub Actions?**
   - A. Require a real Snowflake account in CI.
   - B. Check the SQL in tests; run live tests only when someone sets a secret.
   - C. No Snowflake tests.
   - **Recommend B.** CI stays free and green; people with Snowflake can still prove it live.

6. **Does the one-command demo need Snowflake?**
   - A. Replace today's Postgres demo.
   - B. Keep the Postgres demo; Snowflake is docs and tests.
   - C. Add a second demo that needs a Snowflake account, and run it in CI.
   - **Recommend B.** The public demo and CI stay as they are.

7. **Snowflake's own masking policies, or datagrant views like Postgres?**
   - A. Use Snowflake masking policies as the grant.
   - B. Keep datagrant masked views (same five names as Postgres).
   - C. Support both in this version.
   - **Recommend B.** One way to grant, one way to revoke, one receipt.

## Decisions already on record (Chris)

1. **Warehouses were not M2.** Originally "v0.5.0+". M3 moved them to **v0.6.0+**. This design is that milestone.
2. **Rate limits stay out.**
3. **`max_rows` stays out.**
4. **No break-glass.** Emergency path is a reviewed policy edit to `approval: auto`.
5. **M3 was ops hardening, not a second engine.** Released as v0.5.0.
