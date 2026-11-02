# Requirements (draft)

**Status:** Draft, awaiting maintainer approval (task `I-1`).

## Functional
| ID | Requirement |
| --- | --- |
| FR-1 | Accept a grant request: database, table, columns, optional row filter, duration, purpose, requester. |
| FR-2 | Validate requests against a local policy file; deny by default. |
| FR-3 | Create a Postgres view limited to requested columns and rows, and a role with `VALID UNTIL` expiry. |
| FR-4 | Apply per-column masking (redact, hash, partial, Presidio-detected PII). |
| FR-5 | Revoke on demand and via an idempotent expiry sweep. |
| FR-6 | Emit a signed JSON access receipt per grant; provide `receipt verify`. |
| FR-7 | Optionally summarize audited queries made during the grant. |

## Non-functional
| ID | Requirement |
| --- | --- |
| NFR-1 | Never log or persist regulated data values. |
| NFR-2 | Fail closed: if revoke fails, alert and retry; never extend access silently. |
| NFR-3 | Maximum grant duration enforced by policy. |
| NFR-4 | Signing keys are never printed or logged. |
| NFR-5 | Python 3.10+, Linux/macOS/Windows CLI. |
| NFR-6 | ≥90% test coverage; integration tests against real Postgres in CI. |

## Open questions
- Approval workflow in v1: policy-only, or a second-person approve command?
- Receipt key storage: file, environment, or KMS plug-in?
