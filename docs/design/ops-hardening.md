# Design: ops hardening (v0.5.0 / M3)

Status: proposed. Not implemented. This is the M3 design and execution plan (ops hardening, target v0.5.0) from the v1.0 plan Chris authorized. Scope below includes Chris's earlier decisions (warehouses v0.5.0+, no rate limits, no `max_rows`) and how this milestone interprets them. Construction must not start until this document is approved in [audit.md](../../aidlc-docs/audit.md). Roadmap: [ROADMAP.md](../../ROADMAP.md).

Grounded in the v0.4.0 code on `main` (`src/datagrant/cli.py`, `pg/grant.py`, `pg/revoke.py`, `receipt.py`, `outbox.py`, `keys.py`, `docs/security.md`, `docs/operations.md`).

## Goal

v0.4.0 can issue, approve, receipt and revoke Postgres grants. Operators who run it in anger still hit documented gaps: two writers can both pass the concurrent-grant cap; `preflight` only warns about `PUBLIC` defaults that every grant role inherits; grant DDL can land SCRAM verifiers and hash-key parameters in the server log; the host has no single "is this safe to `--apply`" command; the receipt log is not checked the way key files are.

M3 hardens **operations of the Postgres CLI** so a single-writer, bastion-style install fails closed on those host and database mistakes. It does not add a warehouse, a daemon, or a ticket system.

Out of scope for M3: Snowflake and BigQuery (see [Warehouses](#warehouses)), rate limits, `max_rows`, break-glass, a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, SECURITY INVOKER views, signing-key rotation that keeps one log, PyPI publish, and anything only a DSN holder can bypass without a real enforcement point. Emergency access stays a reviewed policy edit to `approval: auto`.

## Warehouses

Chris parked other warehouses at **v0.5.0+** during M2 so they would not land in v0.4.0. M3's target is also v0.5.0, but the theme is ops hardening, not a second engine.

**Verdict: warehouses are later (v0.6.0+), not M3.** A Snowflake or BigQuery grant path is a new SQL dialect, catalog, identity, revoke, and demo. It would swallow this milestone and leave the Postgres production gaps open. "v0.5.0+" meant "not M2", not "must share the next version number". Rate limits and `max_rows` stay out (Chris).

## What is already true (do not rebuild)

| Behavior | Where | Keep as-is |
| --- | --- | --- |
| `preflight` warns on `PUBLIC` CONNECT / TEMP / CREATE | `pg/grant.py` `_PREFLIGHT` | M3 may add an optional fail-closed mode on access-creating paths. Default stays warn-only. Revoke and sweep stay unblocked. |
| Grant DDL uses `SET LOCAL search_path = pg_catalog, pg_temp` | `apply_plan` | Keep. M3 may add `SET LOCAL log_statement` in the same transaction when the admin can SET that GUC. |
| Revoke commits lockout, then terminates sessions, then drops | `pg/revoke.py` | Keep. Needs `pg_signal_backend` (or superuser); today that is a runtime error, not a preflight check. Access removal must not fail open on preflight or logging GUC. |
| Receipt log, file sink, and outbox flush use `fcntl.flock` on POSIX | `receipt.py`, `outbox.py` | Keep. Windows is still one writer per log (documented). A DB advisory lock does not replace the file lock. |
| Key files: `O_NOFOLLOW`, regular file, POSIX 0600 | `keys.py` | Keep. M3 applies the same refusal to the receipt log on access-creating `--apply`; `revoke` and `sweep` warn and still revoke. The policy file is configuration (often 0644 in a checkout); warn by default, optional refuse. |
| Concurrent-cap count is `status = 'active' AND expires_at > now()` | `count_active_grants` | Keep the count. M3 serializes writers with a session lock held across autocommit transactions. |
| CLI connections use `autocommit=True` | `cli.py` `_connect` | Keep. `approve` counts the cap, then `apply_plan` in later transactions on the same connection. A transaction-scoped lock is released at COMMIT and does not cover that window. |
| One documented writer | `docs/security.md` | M3 makes that real on one database via a lock. Two hosts with two logs remain two writers. |
| `policy.version` is `1`; unknown keys are errors | `parse_policy` | New keys optional. Omitting them is v0.4.0. |
| Receipts version 1; v0.4.0 JSONL still verifies | `receipt.py` | No new events required for M3. |
| Demo is local two-person with one approver | `scripts/demo.py` | Stay that way unless a later docs PR extends it. |
| Admin need not be superuser | `docs/operations.md` | The admin must be able to `pg_signal_backend` (or be superuser). `SET LOCAL log_statement` needs superuser or PG15+ `GRANT SET ON PARAMETER log_statement`. |

## Scope judgment

| Candidate | Verdict | Why |
| --- | --- | --- |
| Session `pg_advisory_lock` on mutating `--apply`, unlock in `finally` | **Keep** (recommended) | Closes the concurrent-cap race across autocommit transactions. `pg_advisory_xact_lock` is released at COMMIT and cannot cover `approve`. Open question 2. |
| `pg_advisory_xact_lock` | **Cut** | Released at COMMIT. CLI is autocommit; cap count and `apply_plan` are separate transactions. |
| Per-requester `SELECT ... FOR UPDATE` only | **Cut** as the only fix | Helps the cap, not two `sweep --apply` processes dropping the same role. |
| Optional fail-closed preflight on access-creating paths | **Keep** (recommended, default off) | `PUBLIC` CONNECT/TEMP/CREATE is already detected. Never block revoke or sweep. Open question 3. |
| Fail-closed preflight on revoke/sweep | **Cut** | Access removal must not fail open. |
| `datagrant doctor` | **Keep** (recommended) | One command for keys, policy, DSN, preflight, `pg_signal_backend`, `log_statement` SET privilege, receipt log, sink cursor. Open question 4. |
| Fold doctor into `preflight` | **Cut** (recommended) | `preflight --apply` creates state. Doctor should not create schemas. |
| Receipt-log 0600 on access-creating `--apply` | **Keep** (recommended) | Same bar as keys for `request`, `approve`, `preflight --apply`. `revoke` and `sweep` warn, still revoke, and report the receipt problem (exit 3). Dry runs warn. |
| Policy-file 0600 refuse on `--apply` | **Cut** as the default | A checkout `policy.yaml` is 0644. Warn by default; optional `strict_policy_permissions` refuses access-creating `--apply` only. Open question 5. |
| `SET LOCAL log_statement = 'none'` when the admin can SET it | **Keep** (recommended) | Known leak of verifiers and hash-key parameters. Needs superuser or PG15+ GRANT. Open question 6. |
| Require a server GUC `log_statement = none` | **Cut** | Too rigid for shared clusters; SET LOCAL covers datagrant's session when permitted. |
| Windows `flock` | **Cut** | No portable equivalent. The advisory lock covers DB mutations on Windows; the receipt log stays one writer there. |
| Snowflake / BigQuery | **Cut** (v0.6.0+) | See [Warehouses](#warehouses). |
| Request rate limits | **Cut** | Chris. No daemon. DSN holders skip the CLI. |
| `max_rows` at grant time | **Cut** | Chris. Racy `COUNT(*)`; row limits stay `row_filters`. |
| Break-glass | **Cut** | Reviewed policy edit to `auto`. |
| Hosted bastion / wrapper as code | **Cut** | Document the pattern. Do not ship a service. |
| SECURITY INVOKER views | **Cut** | Grant semantics, not ops. RLS bypass stays a known limit. |
| Multi-key receipt verify / in-place signing-key rotation | **Cut** | Keep "one key per log". Rotation stays archive-and-start-a-new-log. |
| PyPI publish | **Cut** | Maintainer. CI can grow a wheel job later; not this milestone. |
| `policy.version` bump | **Cut** | Omit new keys = v0.4.0. |

## Operator configuration

`policy.version` stays `1`. Unknown keys remain errors. New keys are optional.

```yaml
version: 1
approval: two-person
approvers: [sec]
max_duration: 8h
strict_preflight: true              # optional; omit = warn-only (v0.4.0)
strict_policy_permissions: true     # optional; omit = warn on a group/other-readable policy file
```

Validation (`datagrant policy check` enforces this offline):

- `strict_preflight`: boolean. Omitted or `false` keeps today's warnings. `true` means `--apply` on **access-creating** paths (`request`, `approve`, and `preflight --apply`) refuses (exit 1) when `_PREFLIGHT` returns any row. **`revoke` and `sweep` never refuse for this reason.**
- `strict_policy_permissions`: boolean. Omitted or `false` means POSIX `--apply` **warns** if the policy file is not owner-only (0644 checkouts keep working). `true` means `--apply` on **access-creating** paths refuses (exit 1) if the policy file is group/other-readable. **`revoke` and `sweep` never refuse for this reason.**
- Dataset- or table-level `strict_preflight` or `strict_policy_permissions` is an unknown-key error.

No other policy keys in M3. Rate limits and `max_rows` are not added.

## CLI

**Advisory lock.** Mutating `--apply` that talks to Postgres takes a **session-level** lock on `DATAGRANT_ADVISORY_LOCK_KEY` **before** the concurrent-grant cap count (and before any other mutating work). Unlock with `pg_advisory_unlock` in a `finally` block only if this session acquired it. Session close is the backstop if the process dies before `finally`. Do **not** use `pg_advisory_xact_lock`: that lock is released at COMMIT, and `_connect` uses `autocommit=True` (`cli.py`), so `approve` counts the cap in one transaction and `apply_plan` runs in later ones. Do **not** use `hashtext()` (or any SQL hash of a string) as the key; the key is a documented module-level bigint constant:

```
DATAGRANT_ADVISORY_LOCK_KEY = 0x64677401  # 1684501505; 'dgt' + 0x01
```

- **Access-creating** (`request`, `approve`, `preflight --apply`): `SET lock_timeout` (about 30s; tests may shorten `LOCK_WAIT_SECONDS`), then `pg_advisory_lock`, then `RESET lock_timeout`. On timeout, fail closed with exit 3 and `another writer holds the datagrant lock (pid N)` (pids from `pg_locks` where `locktype = 'advisory'` and the key matches). No grant is created.
- **`revoke` / `sweep`:** `pg_try_advisory_lock`. On contention, proceed **without** the lock and print a stderr warning naming the holding pid(s). Access removal only lowers the cap count, so it cannot double-issue.

`PUBLIC` can `EXECUTE pg_advisory_lock`, so any CONNECT role can hold the key. The lock is a coordination aid, not a security boundary. Dry runs do not lock. The receipt JSONL is still one process per file (existing POSIX flock; Windows documented).

**`datagrant doctor`.** New command. Shared flags: `--dsn`, `--policy`, `--signing-key`, `--hash-key`, `--receipt-log`, `--receipt-sink` (and mode). No `--apply` (read-only). Checks, in order: key files (same rules as today), policy parse, policy-file mode on POSIX (warn unless `strict_policy_permissions`), receipt-log/cursor file mode on POSIX, DSN connect, `preflight` warnings, `pg_signal_backend` (or superuser), ability to `SET log_statement` (superuser or PG15+ `has_parameter_privilege(..., 'log_statement', 'SET')`), receipt-log chain head, optional sink cursor readability. Exit 0 if all pass; exit 1 with reasons if any fail (warnings-only policy mode does not fail unless `strict_policy_permissions`); exit 2 on usage. `--json` lists each check. Does not create schemas, keys, or grants, and does not `SET log_statement`.

**`preflight`.** Unchanged job: create state with `--apply`, print PUBLIC warnings. If `strict_preflight` is true, `preflight --apply`, `request --apply`, and `approve --apply` fail when warnings remain. `revoke` and `sweep` ignore this key.

**Policy-file and receipt-log permissions.** On POSIX, using the opened fd (`O_NOFOLLOW`):

- **Receipt log:** access-creating `--apply` (`request`, `approve`, `preflight --apply`) **refuses** if it is not a regular file or is group/other-readable (same bar as keys). `revoke` and `sweep` **warn and still revoke** (access removal must not fail open), then report the receipt-log problem the same way as today's receipt write failure (exit 3). Dry runs warn. Windows: regular file only.
- **Policy file:** `--apply` **warns** if it is not a regular file or is group/other-readable. With `strict_policy_permissions: true`, access-creating `--apply` (`request`, `approve`, `preflight --apply`) **refuses**; `revoke` and `sweep` still only warn. Windows: regular file only.

**Admin session logging.** `apply_plan` issues `SET LOCAL log_statement = 'none'` next to the existing `search_path` pin **when the connected role can SET that GUC** (superuser, or PostgreSQL 15+ `GRANT SET ON PARAMETER log_statement TO <admin>` as allowed by [docs/operations.md](../operations.md) for a non-superuser admin). If the role cannot SET it:

- Access-creating `--apply` (`request`, `approve`) **refuses** with a clear message naming `SET log_statement` and the GRANT (or superuser) requirement.
- `revoke` and `sweep` **proceed without** `SET LOCAL log_statement` (access removal must not fail open). Doctor reports the missing privilege.

Residual: a superuser or server-wide logging collector can still capture parameters; document that.

Exit codes stay 0-4. Doctor uses 0/1/2. Strict preflight failures and missing `log_statement` SET privilege on access-creating `--apply` are exit 1 (failed), not usage.

## Threat and ops notes

- **DSN holders still bypass the CLI.** Locks, doctor, and strict preflight are workflow and host controls. To treat them as enforced, run datagrant on a bastion that holds `DATAGRANT_DSN` (same OIDC story).
- **The advisory lock is per database, not per cluster.** Two DSNs to two databases do not serialize. Two processes with two receipt logs on one host still need the file lock / one-writer rule.
- **The lock is session-scoped, not transaction-scoped.** `pg_advisory_unlock` in `finally` releases it when this session acquired it; a crash holds it until the backend session dies. Doctor does not wait on the lock (it is read-only).
- **Revoke and sweep never wait.** They use `pg_try_advisory_lock`. If the key is held, they proceed without the lock and warn with the holding pid(s) from `pg_locks`.
- **Access-creating `--apply` has a bounded wait.** About 30s via `lock_timeout`, then fail closed (exit 3, no grant). `RESET lock_timeout` runs after the wait so later `SELECT ... FOR UPDATE` is not bound.
- **The lock is not a security boundary.** `PUBLIC` can `EXECUTE pg_advisory_lock`, so a grant role (LOGIN, CONNECT) or any other CONNECT role can `SELECT pg_advisory_lock(1684501505)` and stall `request`/`approve`/`preflight --apply` until timeout. It cannot stall `revoke`/`sweep`. Run datagrant as the only writer when you need the cap race closed.
- **`SET LOCAL log_statement` needs a privilege the default non-superuser admin does not have.** Without `GRANT SET ON PARAMETER log_statement` (PG15+) or superuser, SET fails with permission denied. Access-creating paths refuse; revoke and sweep continue. Superuser `log_min_duration_statement = 0` with parameter logging can still leak. Residual, documented.
- **Doctor is a snapshot.** Passing doctor and then chmod 644 the receipt log before `--apply` is a TOCTOU; `--apply` re-checks the files it uses.
- **No rate limits, no `max_rows`.** Chris. A clock table would look like security and not be.

## Compatibility with v0.4.0

- Policies that omit `strict_preflight` and `strict_policy_permissions` parse and evaluate as today. `policy.version` stays `1`.
- A 0644 `policy.yaml` from a git checkout keeps working (warn on `--apply`; refuse only if `strict_policy_permissions: true` on access-creating paths).
- Receipt JSONL from v0.4.0 remains valid input to `receipts verify`. No new receipt events.
- `make demo` stays local two-person with one approver. CI demo Postgres has PUBLIC defaults that would fail a strict preflight; the demo omits the key. Demo policy files stay 0644.
- Existing keys, DSNs, and runbooks keep working. `doctor` is additive.
- The advisory lock does not change SQL of the grant view or role.
- A non-superuser admin that cannot SET `log_statement` can still `revoke` and `sweep`; it cannot `--apply` a new grant until the GRANT (or superuser) is in place.

## Test plan (each construction PR)

- Advisory lock: two overlapping access-creating `--apply` stubs; the second waits or sees the first's row; concurrent-cap cannot double-insert in a scripted race. Dry run does not lock. Integration: two connections, one holds the lock. The lock is still held after `COMMIT` on an autocommit connection (session lock, not xact). After `pg_advisory_unlock` in `finally`, a second command on the same connection can take the lock. The SQL uses `DATAGRANT_ADVISORY_LOCK_KEY` (0x64677401), not `hashtext()`. A stub that only `COMMIT`s must not drop the lock. `revoke`/`sweep` with the lock held by another connection complete, terminate the grantee session, and warn with the pid. `request`/`approve` time out, fail closed with exit 3, and create no grant (unit with a fake; integration with a short configurable `LOCK_WAIT_SECONDS`). `lock_timeout` is reset after the wait.
- Doctor: missing key, group-readable key, bad policy, unreachable DSN, PUBLIC warning listed, missing `pg_signal_backend` (non-superuser stub), missing `log_statement` SET privilege, unreadable cursor; `--json` shape; exit 0 on a clean temp dir; doctor does not call `CREATE SCHEMA` and does not `SET log_statement`.
- `strict_preflight`: omitted = warn and grant; `true` = `--apply` on `request`, `approve`, and `preflight` exit 1 when `_PREFLIGHT` is non-empty; **`revoke` and `sweep --apply` proceed under `strict_preflight: true` even when `_PREFLIGHT` is non-empty**; dry run still reports; dataset-level key is a parse error; `policy check` catches a non-boolean.
- File modes: POSIX `request`/`approve`/`preflight --apply` refuse a 0644 **receipt log**; **`revoke`/`sweep` with a 0644 receipt log still drop the role and terminate sessions, warn, and exit 3** (receipt problem reported like a receipt write failure). A 0644 **policy file** warns by default and still applies; with `strict_policy_permissions: true`, `request`/`approve`/`preflight --apply` refuse and **`revoke`/`sweep` proceed**. Dry run warns. Windows regular-file check only.
- `log_statement`: `apply_plan` SQL includes `SET LOCAL log_statement = 'none'` before INSERT/PASSWORD when the role can SET it. Unit test on the statement list. Missing privilege: `request`/`approve --apply` refuse with a message that names `SET log_statement` and the PG15+ GRANT (or superuser); **`revoke` and `sweep` proceed without the SET**. Doctor lists the missing privilege. Superuser (or granted role) path issues the SET.
- Compat: omitted new keys; 0644 policy file; existing OIDC request/approve/revoke integration still passes.
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as M2: one concern per PR, tests and security checks in each, docs last. No warehouse PR. No rate-limit PR. No `max_rows` PR. No break-glass PR.

1. **This PR.** Design, ROADMAP, audit pointer. No runtime.
2. **Advisory lock.** Session lock on mutating `--apply` before the cap count. Access-creating paths: bounded `pg_advisory_lock` then fail closed (exit 3). `revoke`/`sweep`: `pg_try_advisory_lock`, proceed and warn on contention. Unlock in `finally` if acquired. Tests for the concurrent-cap race, try-lock revoke, and timeout. No doctor yet.
3. **`datagrant doctor`.** Read-only host and DB checks (keys, policy parse, DSN, preflight warnings, `pg_signal_backend`, `log_statement` SET privilege, receipt log, sink cursor). `--json`. Does not create state.
4. **`strict_preflight` and file modes.** Policy keys (default off). `strict_preflight` gates access-creating `--apply` only. POSIX receipt-log 0600 refusal on access-creating `--apply` only; `revoke`/`sweep` warn, revoke, exit 3. Policy-file warn by default; `strict_policy_permissions` refuses access-creating `--apply` only. Tests as in the test plan.
5. **`SET LOCAL log_statement = 'none'`** in `apply_plan` when permitted; refuse access-creating `--apply` if not; revoke/sweep proceed without it. Tests on the statement list and the missing-privilege paths.
6. **Docs, runbook, CHANGELOG Unreleased, v0.5.0 prep (no tag).** `docs/cli.md`, `docs/security.md`, `docs/operations.md`, this design marked implemented.

## Open questions

Each item needs Chris's call before construction. Recommended picks are the proposed default if the design is approved as-is. They are not yet approved.

1. **Do warehouses belong in M3 (v0.5.0) or later?**
   - A. Put Snowflake/BigQuery in M3.
   - B. M3 is Postgres ops only; warehouses wait for v0.6.0+.
   - C. Stub a warehouse interface in M3, implement later.
   - **Recommend B.** Chris's "v0.5.0+" meant not M2; a second engine would swallow ops hardening, which is the production gap on the Postgres CLI.

2. **How should two overlapping `--apply` processes be serialized?**
   - A. Keep documented one-writer; no lock.
   - B. Session `pg_advisory_lock` on a documented bigint constant, taken before the cap count, released with `pg_advisory_unlock` in a `finally` block (session close as backstop).
   - C. Per-requester row lock only when counting concurrent grants, or `pg_advisory_xact_lock`.
   - **Recommend B.** `pg_advisory_xact_lock` is released at COMMIT; the CLI is autocommit and `approve` spans several transactions, so only a session lock held for the command closes the cap race.

3. **Should remaining PUBLIC preflight warnings block `--apply`?**
   - A. Warn only (v0.4.0).
   - B. Always fail `--apply` (including revoke/sweep) if `_PREFLIGHT` is non-empty.
   - C. Optional `strict_preflight: true` in policy; omit = warn-only; gates `request`, `approve`, and `preflight --apply` only; never revoke or sweep.
   - **Recommend C.** Production installs can opt in; CI and `make demo` keep working without the key; access removal must not fail open.

4. **New `doctor` command, or extend `preflight`?**
   - A. Extend `preflight` with keys, log, sink, `pg_signal_backend`, and `log_statement` SET privilege.
   - B. Add `datagrant doctor` (read-only) and leave `preflight` as state plus PUBLIC warnings.
   - C. Runbook checklist only; no new command.
   - **Recommend B.** `preflight --apply` creates schemas; doctor should not. Operators need one non-mutating "safe to run" command.

5. **Should the policy file require POSIX 0600 on `--apply`?**
   - A. Refuse `--apply` if the policy file is group/other-readable (same as keys). Breaks a 0644 git checkout.
   - B. Warn by default; optional `strict_policy_permissions: true` refuses `--apply` on access-creating paths only. Receipt-log 0600 refusal on access-creating `--apply` only; `revoke` and `sweep` warn, still revoke, and exit 3.
   - C. Leave policy-file mode unchecked; still refuse a group/other-readable receipt log.
   - **Recommend B.** A checkout `policy.yaml` is 0644; the policy is configuration, not a key file. The receipt log fails closed for new access, while `revoke` and `sweep` always remove access.

6. **How to stop grant DDL from logging verifiers and hash-key parameters?**
   - A. Document only (operators set the GUC).
   - B. `SET LOCAL log_statement = 'none'` when the admin can SET it (superuser or PG15+ `GRANT SET ON PARAMETER log_statement TO <admin>`); access-creating `--apply` refuses if not; revoke and sweep proceed without it.
   - C. Refuse `--apply` unless the server GUC is already `none`.
   - **Recommend B.** It closes the known leak for datagrant's session without dictating cluster logging, and it does not block access removal when a non-superuser admin lacks the GRANT. Superuser collectors remain a documented residual.

## Decisions already on record (Chris)

1. **Warehouses are not M2.** Originally "v0.5.0+". This design proposes **v0.6.0+** so M3 can be ops hardening (open question 1).
2. **Rate limits stay out.**
3. **`max_rows` stays out.**
4. **No break-glass** (M2). Emergency path is a reviewed policy edit to `approval: auto`.
