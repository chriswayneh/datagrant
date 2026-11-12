# Execution plan

**Status:** Approved by Chris Hickman 2026-11-02 5:20 PM CT (see [audit.md](../audit.md), execution-plan approval row); closes task `I-1`. Construction follows AGENTS.md: one unit per PR, tests in each.

## Stages
| Stage | Applies? | Notes |
| --- | --- | --- |
| Workspace detection | ✅ Done | Greenfield |
| Reverse engineering | ⏭ Skip | No existing code to analyze |
| Requirements / user stories | ✅ Done | requirements.md, user-stories.md |
| Application design | ✅ Done | application-design.md |
| Units of work | ✅ Done | Table below (also units-of-work.md) |
| Functional design | ✅ Per unit | Short section in each PR / construction/functional-design.md |
| NFR requirements / design | ✅ Light | Security guardrails from AGENTS.md; no perf/scale design for a CLI |
| Infrastructure design | ⏭ Skip | No hosted service; Postgres only via CI service container |
| Code generation + build/test | ✅ Per unit | Unit tests + real-Postgres integration tests in CI |
| Operations | ✅ Light | Runbook for sweep scheduling and key handling |

## Construction units (PR order)
| # | Unit | Depends on | Done when |
| --- | --- | --- | --- |
| U1 | Policy loader + evaluator (`policy.py`) | None | YAML schema validated; deny-by-default; max duration; explain denials; tests |
| U2 | Grant engine: Postgres view + expiring role, grant state table (`pg/grant.py`, `pg/state.py`) | U1 | Transactional create; quoted identifiers; validated row filter; dry-run SQL; integration tests |
| U3 | Masking (`pg/mask.py`) | U2 | redact/hash(pgcrypto HMAC)/partial/null; raw values unreachable via grant role |
| U4 | Expiry, revoke, sweep (`revoke.py`) | U2 | Sessions terminated, view+role dropped, idempotent, fail-closed exit codes |
| U5 | Signed receipts (`receipt.py`, `keygen`) | U2 | ed25519 sign/verify, canonical JSON, key file 0600 + env override, tamper test |
| U6 | CLI wiring + optional two-person approve | U1–U5 | `request/approve/revoke/sweep/list/receipt verify`; one-time password printed once |
| U7 | One-command demo | U6 | Script seeds fictional data in local Postgres and walks request→query→expire→verify |
| U8 | Docs | U7 | README quickstart, policy reference, security notes, runbook |

## Risks
- RLS bypass via view owner (mitigated in U2/U3 tests).
- Revoke failures (fail closed, retried by sweep).

## Post-v0.3.0: M2 / v0.4.0 (implemented)

v0.1.0 units U1–U8 above stay the approved original plan. Chris authorized a v1.0 plan that names **M2 = approvals and policy limits**, target v0.4.0.

Implemented (PRs #33 to #38). Design: [docs/design/approvals-policy-limits.md](../../docs/design/approvals-policy-limits.md). v0.4.0 released 2026-11-10. No break-glass.

## Post-v0.4.0: M3 / v0.5.0 (implemented)

Chris authorized a v1.0 plan that names **M3 = ops hardening**, target v0.5.0. Warehouses (Snowflake/BigQuery) are proposed for **v0.6.0+**, not this milestone. Rate limits and `max_rows` stay out. No break-glass.

Implemented (PRs #40 to #45). Design: [docs/design/ops-hardening.md](../../docs/design/ops-hardening.md). v0.5.0 is ready, release pending; not tagged.
