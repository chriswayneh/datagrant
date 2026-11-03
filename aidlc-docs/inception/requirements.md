# Requirements (draft)

**Status:** Approved by Chris Hickman, 2026-11-02 (task `I-1`).

## Users
- **AI/ML developer**: needs a narrow, temporary slice of regulated data (PHI/PII) to build, debug, or evaluate a model or pipeline.
- **Data owner / approver**: writes the policy that says who may see what, for how long, and how it is masked.
- **Security / compliance reviewer**: needs evidence of who had access to what, why, and when it ended.
- **DBA / platform engineer**: runs datagrant against Postgres and the expiry sweep.

## Problem
Developers on regulated data usually get standing, over-broad read access (or full production copies) because fine-grained, time-boxed access is slow to set up by hand. That creates HIPAA minimum-necessary and PII-exposure risk, and leaves weak audit evidence. datagrant makes the narrow, expiring, masked grant the easy path, from a CLI, with a verifiable receipt.

## Functional
| ID | Requirement |
| --- | --- |
| FR-1 | `datagrant request`: database, schema.table, columns, optional row filter, duration, purpose, requester. |
| FR-2 | Evaluate the request against a local, version-controlled policy file (YAML); deny by default; explain denials. |
| FR-3 | Create a per-grant Postgres view limited to the requested columns/rows, and a login role with `VALID UNTIL` granted only on that view. |
| FR-4 | Per-column masking set by policy: `redact`, `hash` (keyed), `partial`, `null`, `passthrough`. |
| FR-5 | `datagrant revoke <id>` and an idempotent `datagrant sweep` that drops expired roles/views and terminates their sessions. |
| FR-6 | Emit an ed25519-signed JSON receipt per grant event (issued, revoked, expired); `datagrant receipt verify`. |
| FR-7 | `datagrant list` / `status` showing active grants and time remaining. |
| FR-8 | `--dry-run` prints the SQL plan without executing it. |

## Non-functional
| ID | Requirement |
| --- | --- |
| NFR-1 | Never log, print, or persist regulated data values (receipts hold metadata only: columns, filter text, policy hash). |
| NFR-2 | Fail closed: on any error during grant, roll back; if revoke fails, exit non-zero and retry on next sweep; never extend access silently. |
| NFR-3 | Maximum grant duration enforced by policy; `VALID UNTIL` is a backstop, sweep is the primary revoker. |
| NFR-4 | Signing keys never printed or logged; key file permissions checked (0600). |
| NFR-5 | Python 3.11+ (requires-python >=3.11), psycopg 3; Linux/macOS (Windows best-effort). |
| NFR-6 | All SQL identifiers quoted via `psycopg.sql`; row filters parsed/validated, never interpolated raw. |
| NFR-7 | datagrant's own admin connection uses a dedicated least-privilege role (CREATEROLE + ownership of a `datagrant` schema), not superuser. |
| NFR-8 | ≥90% unit coverage; integration tests against real Postgres in CI. Fictional data only. |

## HIPAA / PII considerations (not legal advice)
- Supports the HIPAA **minimum necessary** standard and access-control/audit expectations of the Security Rule; datagrant alone does **not** make a system HIPAA compliant.
- Masked ≠ de-identified: hashed or partial values may still be PHI under HIPAA (Safe Harbor/Expert Determination are out of scope).
- Receipts are evidence of grants, not of every query; per-query audit relies on Postgres logging/pgAudit if enabled.
- Grant views run with owner privileges; base-table RLS policies may be bypassed. This is documented and tested.

## Out of scope (v1)
- Databases other than Postgres; GUI/web UI; long-running server/daemon.
- Multi-party approval workflows, SSO/IdP integration, ticketing integration.
- Automatic PII discovery (e.g. Presidio) is a candidate for later.
- Data copies/exports, synthetic data generation, query-level DLP.

See [open-questions.md](open-questions.md).
