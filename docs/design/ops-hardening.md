# Design: ops hardening (v0.5.0 / M3)

Status: proposed. Not implemented. This is the M3 design and execution plan (ops hardening, target v0.5.0) from the v1.0 plan Chris authorized. Scope below includes Chris's earlier decisions (warehouses v0.5.0+, no rate limits, no `max_rows`) and how this milestone interprets them. Construction must not start until this document is approved in [audit.md](../../aidlc-docs/audit.md). Roadmap: [ROADMAP.md](../../ROADMAP.md).

Grounded in the v0.4.0 code on `main` (`src/datagrant/cli.py`, `pg/grant.py`, `pg/revoke.py`, `receipt.py`, `outbox.py`, `keys.py`, `docs/security.md`, `docs/operations.md`).

## Goal

v0.4.0 can issue, approve, receipt and revoke Postgres grants. Operators who run it in anger still hit documented gaps: two writers can both pass the concurrent-grant cap; `preflight` only warns about `PUBLIC` defaults that every grant role inherits; grant DDL can land SCRAM verifiers and hash-key parameters in the server log; the host has no single "is this safe to `--apply`" command; policy and receipt-log files are not checked the way key files are.

M3 hardens **operations of the Postgres CLI** so a single-writer, bastion-style install fails closed on those host and database mistakes. It does not add a warehouse, a daemon, or a ticket system.

Out of scope for M3: Snowflake and BigQuery (see [Warehouses](#warehouses)), rate limits, `max_rows`, break-glass, a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, SECURITY INVOKER views, signing-key rotation that keeps one log, PyPI publish, and anything only a DSN holder can bypass without a real enforcement point. Emergency access stays a reviewed policy edit to `approval: auto`.

## Warehouses

Chris parked other warehouses at **v0.5.0+** during M2 so they would not land in v0.4.0. M3's target is also v0.5.0, but the theme is ops hardening, not a second engine.

**Verdict: warehouses are later (v0.6.0+), not M3.** A Snowflake or BigQuery grant path is a new SQL dialect, catalog, identity, revoke, and demo. It would swallow this milestone and leave the Postgres production gaps open. "v0.5.0+" meant "not M2", not "must share the next version number". Rate limits and `max_rows` stay out (Chris).

## What is already true (do not rebuild)

| Behavior | Where | Keep as-is |
| --- | --- | --- |
| `preflight` warns on `PUBLIC` CONNECT / TEMP / CREATE | `pg/grant.py` `_PREFLIGHT` | M3 may add an optional fail-closed mode. Default stays warn-only. |
| Grant DDL uses `SET LOCAL search_path = pg_catalog, pg_temp` | `apply_plan` | Keep. M3 may add `SET LOCAL log_statement` in the same transaction. |
| Revoke commits lockout, then terminates sessions, then drops | `pg/revoke.py` | Keep. Needs `pg_signal_backend` (or superuser); today that is a runtime error, not a preflight check. |
| Receipt log, file sink, and outbox flush use `fcntl.flock` on POSIX | `receipt.py`, `outbox.py` | Keep. Windows is still one writer per log (documented). A DB advisory lock does not replace the file lock. |
| Key files: `O_NOFOLLOW`, regular file, POSIX 0600 | `keys.py` | Keep. M3 may apply the same checks to the policy file and receipt log on `--apply`. |
| Concurrent-cap count is `status = 'active' AND expires_at > now()` | `count_active_grants` | Keep the count. M3 serializes the writers. |
| One documented writer | `docs/security.md` | M3 makes that real on one database via a lock. Two hosts with two logs remain two writers. |
| `policy.version` is `1`; unknown keys are errors | `parse_policy` | New keys optional. Omitting them is v0.4.0. |
| Receipts version 1; v0.4.0 JSONL still verifies | `receipt.py` | No new events required for M3. |
| Demo is local two-person with one approver | `scripts/demo.py` | Stay that way unless a later docs PR extends it. |

## Scope judgment

| Candidate | Verdict | Why |
| --- | --- | --- |
| Session `pg_advisory_lock` on mutating `--apply` | **Keep** (recommended) | Closes the concurrent-cap race and overlapping grant/revoke/sweep on one database. No daemon. Open question 2. |
| Per-requester `SELECT ... FOR UPDATE` only | **Cut** as the only fix | Helps the cap, not two `sweep --apply` processes dropping the same role. |
| Optional fail-closed preflight | **Keep** (recommended, default off) | `PUBLIC` CONNECT/TEMP/CREATE is already detected. Refusing `--apply` when warnings remain is the production bar; omit = v0.4.0. Open question 3. |
| `datagrant doctor` | **Keep** (recommended) | One command for keys, policy, DSN, preflight, `pg_signal_backend`, receipt log, sink cursor. Open question 4. |
| Fold doctor into `preflight` | **Cut** (recommended) | `preflight --apply` creates state. Doctor should not create schemas. |
| Policy file and receipt-log 0600 on `--apply` | **Keep** (recommended) | Same bar as keys. Dry runs warn. Open question 5. |
| `SET LOCAL log_statement = 'none'` in grant/revoke transactions | **Keep** (recommended) | Known leak of verifiers and hash-key parameters. Open question 6. |
| Require a server GUC `log_statement = none` | **Cut** | Too rigid for shared clusters; SET LOCAL covers datagrant's session. |
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
strict_preflight: true   # optional; omit = warn-only (v0.4.0)
```

Validation (`datagrant policy check` enforces this offline):

- `strict_preflight`: boolean. Omitted or `false` keeps today's warnings. `true` means `--apply` on `request`, `approve`, `revoke`, `sweep`, and `preflight` refuses (exit 1) when `_PREFLIGHT` returns any row.
- Dataset- or table-level `strict_preflight` is an unknown-key error.

No other policy keys in M3. Rate limits and `max_rows` are not added.

## CLI

**Advisory lock.** Mutating `--apply` that talks to Postgres (`request`, `approve`, `revoke`, `sweep`, `preflight --apply`) takes `pg_advisory_lock` on a fixed key in the current database (for example `hashtext('datagrant')`) inside the same session, before counting grants or writing state, and holds it until commit or rollback. Dry runs do not lock. A second `--apply` on that database waits. The receipt JSONL is still one process per file (existing POSIX flock; Windows documented).

**`datagrant doctor`.** New command. Shared flags: `--dsn`, `--policy`, `--signing-key`, `--hash-key`, `--receipt-log`, `--receipt-sink` (and mode). No `--apply` (read-only). Checks, in order: key files (same rules as today), policy parse, policy/receipt-log/cursor file mode on POSIX, DSN connect, `preflight` warnings, `pg_signal_backend` (or superuser), receipt-log chain head, optional sink cursor readability. Exit 0 if all pass; exit 1 with reasons if any fail; exit 2 on usage. `--json` lists each check. Does not create schemas, keys, or grants.

**`preflight`.** Unchanged job: create state with `--apply`, print PUBLIC warnings. If `strict_preflight` is true, `--apply` that would grant or revoke also fails when warnings remain.

**Policy and receipt-log permissions.** On POSIX `--apply`, refuse if the policy file or receipt log is not a regular file or is group/other-readable, using the opened fd (`O_NOFOLLOW`), matching keys. Dry runs warn. Windows: regular file only.

**Admin session logging.** `apply_plan` and the revoke/sweep transactions issue `SET LOCAL log_statement = 'none'` next to the existing `search_path` pin. Residual: a superuser or server-wide logging collector can still capture parameters; document that.

Exit codes stay 0-4. Doctor uses 0/1/2. Strict preflight failures are exit 1 (failed), not usage.

## Threat and ops notes

- **DSN holders still bypass the CLI.** Locks, doctor, and strict preflight are workflow and host controls. To treat them as enforced, run datagrant on a bastion that holds `DATAGRANT_DSN` (same OIDC story).
- **The advisory lock is per database, not per cluster.** Two DSNs to two databases do not serialize. Two processes with two receipt logs on one host still need the file lock / one-writer rule.
- **Waiting on the lock is not a timeout story in M3.** A stuck `--apply` holds the lock until the session dies. Operators already run one writer; doctor does not wait on the lock (it is read-only).
- **`SET LOCAL log_statement` is session-local.** It does not change the cluster GUC. Superuser `log_min_duration_statement = 0` with parameter logging can still leak. Residual, documented.
- **Policy 0600 does not encrypt the policy.** It stops casual reads on a shared host. Anyone with the DSN still reads Postgres.
- **Doctor is a snapshot.** Passing doctor and then chmod 644 the policy before `--apply` is a TOCTOU; `--apply` re-checks the files it uses.
- **No rate limits, no `max_rows`.** Chris. A clock table would look like security and not be.

## Compatibility with v0.4.0

- Policies that omit `strict_preflight` parse and evaluate as today. `policy.version` stays `1`.
- Receipt JSONL from v0.4.0 remains valid input to `receipts verify`. No new receipt events.
- `make demo` stays local two-person with one approver. CI demo Postgres has PUBLIC defaults that would fail a strict preflight; the demo omits the key.
- Existing keys, DSNs, and runbooks keep working. `doctor` is additive.
- The advisory lock does not change SQL of the grant view or role.

## Test plan (each construction PR)

- Advisory lock: two overlapping `--apply` stubs; the second waits or sees the first's row; concurrent-cap cannot double-insert in a scripted race. Dry run does not lock. Integration: two connections, one holds the lock.
- Doctor: missing key, group-readable key, bad policy, unreachable DSN, PUBLIC warning listed, missing `pg_signal_backend` (non-superuser stub), unreadable cursor; `--json` shape; exit 0 on a clean temp dir; doctor does not call `CREATE SCHEMA`.
- `strict_preflight`: omitted = warn and grant; `true` = `--apply` request/approve/revoke/sweep/preflight exit 1 when `_PREFLIGHT` is non-empty; dry run still reports; dataset-level key is a parse error; `policy check` catches a non-boolean.
- File modes: POSIX `--apply` refuses a 0644 policy or receipt log; dry run warns; Windows regular-file check only.
- `log_statement`: `apply_plan` / revoke SQL includes `SET LOCAL log_statement = 'none'` before INSERT/PASSWORD. Unit test on the statement list.
- Compat: omitted new keys; existing OIDC request/approve/revoke integration still passes.
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as M2: one concern per PR, tests and security checks in each, docs last. No warehouse PR. No rate-limit PR. No `max_rows` PR. No break-glass PR.

1. **This PR.** Design, ROADMAP, audit pointer. No runtime.
2. **Advisory lock.** `pg_advisory_lock` on mutating `--apply` (request, approve, revoke, sweep, preflight apply). Tests for the concurrent-cap race. No doctor yet.
3. **`datagrant doctor`.** Read-only host and DB checks (keys, policy parse, DSN, preflight warnings, `pg_signal_backend`, receipt log, sink cursor). `--json`. Does not create state.
4. **`strict_preflight` and file modes.** Policy key (default off). POSIX `--apply` 0600 on policy and receipt log. Tests as in the test plan.
5. **`SET LOCAL log_statement = 'none'`** in `apply_plan` and revoke/sweep transactions. Tests on the statement list.
6. **Docs, runbook, CHANGELOG Unreleased, v0.5.0 prep (no tag).** `docs/cli.md`, `docs/security.md`, `docs/operations.md`, this design marked implemented.

## Open questions

Each item needs Chris's call before construction. Recommended picks are the proposed default if the design is approved as-is.

1. **Do warehouses belong in M3 (v0.5.0) or later?**
   - A. Put Snowflake/BigQuery in M3.
   - B. M3 is Postgres ops only; warehouses wait for v0.6.0+.
   - C. Stub a warehouse interface in M3, implement later.
   - **Recommend B.** Chris's "v0.5.0+" meant not M2; a second engine would swallow ops hardening, which is the production gap on the Postgres CLI.

2. **How should two overlapping `--apply` processes be serialized?**
   - A. Keep documented one-writer; no lock.
   - B. Session `pg_advisory_lock` on mutating `--apply` (one key per database).
   - C. Per-requester row lock only when counting concurrent grants.
   - **Recommend B.** It is the documented ops model made real, covers grant/revoke/sweep, and needs no daemon.

3. **Should remaining PUBLIC preflight warnings block `--apply`?**
   - A. Warn only (v0.4.0).
   - B. Always fail `--apply` if `_PREFLIGHT` is non-empty.
   - C. Optional `strict_preflight: true` in policy; omit = warn-only.
   - **Recommend C.** Production installs can opt in; CI and `make demo` keep working without the key.

4. **New `doctor` command, or extend `preflight`?**
   - A. Extend `preflight` with keys, log, sink, and `pg_signal_backend`.
   - B. Add `datagrant doctor` (read-only) and leave `preflight` as state plus PUBLIC warnings.
   - C. Runbook checklist only; no new command.
   - **Recommend B.** `preflight --apply` creates schemas; doctor should not. Operators need one non-mutating "safe to run" command.

5. **Should the policy file and receipt log require POSIX 0600 on `--apply`?**
   - A. Yes, same checks as key files (regular file, `O_NOFOLLOW`, owner-only); dry runs warn.
   - B. Warn on `--apply`, do not refuse.
   - C. Leave as today (no check).
   - **Recommend A.** Keys already fail closed; policy and the receipt log are the other secrets on disk.

6. **How to stop grant DDL from logging verifiers and hash-key parameters?**
   - A. Document only (operators set the GUC).
   - B. `SET LOCAL log_statement = 'none'` in grant and revoke transactions.
   - C. Refuse `--apply` unless the server GUC is already `none`.
   - **Recommend B.** It closes the known leak for datagrant's session without dictating cluster logging. Superuser collectors remain a documented residual.

## Decisions already on record (Chris)

1. **Warehouses are not M2.** Originally "v0.5.0+". This design proposes **v0.6.0+** so M3 can be ops hardening (open question 1).
2. **Rate limits stay out.**
3. **`max_rows` stays out.**
4. **No break-glass** (M2). Emergency path is a reviewed policy edit to `approval: auto`.
