# Application design (draft)

Python 3.11+, single CLI package `datagrant`, psycopg 3, `cryptography` (ed25519), PyYAML. No server.

## Components
| Component | Module | Responsibility |
| --- | --- | --- |
| CLI | `cli.py` | `request`, `revoke`, `sweep`, `list`, `receipt verify`, `keygen`, `--dry-run`. Arg validation, exit codes. |
| Policy engine | `policy.py` | Load/validate YAML policy; match requester+table+columns+filter+duration; deny by default; returns decision + mask plan + policy hash. Pure, no I/O to DB. |
| Postgres backend | `pg/grant.py` | In one transaction: create `datagrant` schema view `g_<id>` with mask expressions and validated row filter; create role `dg_<id>` `LOGIN VALID UNTIL …`; `GRANT SELECT` on view only. Identifiers via `psycopg.sql`. |
| Masking | `pg/mask.py` | Map mask types to SQL expressions (`redact`→constant, `hash`→keyed HMAC via pgcrypto, `partial`, `null`). |
| Grant store | `pg/state.py` | `datagrant.grants` table: id, role, view, expires_at, status. Source of truth for sweep. |
| Expiry/revocation | `revoke.py` | `revoke`/`sweep`: `pg_terminate_backend` for role sessions, drop view+role, mark revoked; idempotent; run sweep via cron/systemd timer. |
| Receipts | `receipt.py` | Canonical JSON (sorted keys) of grant metadata + policy hash + timestamps; ed25519 signature; append to local JSONL log; verify with public key. |

## Request flow
`request` → policy decision → (dry-run? print SQL) → grant txn → store row → signed `issued` receipt → print one-time password/DSN.
Sweep (cron) → select expired active grants → revoke each → `expired` receipt.

## Key decisions / risks
- Views (not column grants) so masking and row filters live in one object; view owner must not be superuser to limit RLS bypass surprises.
- `VALID UNTIL` only blocks new logins; live sessions require sweep termination.
- Row filters: restricted grammar (column op literal, AND/OR), parsed and re-emitted with parameters.

## Landscape check (hedged; from public descriptions, not verified hands-on)
| Tool | What it does | Gap datagrant targets |
| --- | --- | --- |
| HashiCorp Vault DB secrets engine | Dynamic, TTL'd DB credentials | Creds, not column/row-scoped masked views per request; needs a Vault server |
| Teleport | Identity-aware access proxy, access requests, session audit | Infrastructure-level access; fine-grained masking appears limited/enterprise |
| StrongDM | Commercial access proxy with JIT and audit | Commercial SaaS, proxy-based |
| Cyral | Commercial data-security proxy with masking/policies | Commercial, proxy deployment |
| PostgreSQL Anonymizer | In-DB masking rules/dynamic masking | No JIT request, expiry, or receipts |

**Distinct:** a pip-installable, open-source CLI with no proxy/server that combines policy-as-code, per-request column/row scoping, masking, automatic expiry, and verifiable signed receipts. Real-world use hinges on: working with only a CREATEROLE admin role, cron-based sweep, and receipts that auditors accept. Overlap risk: teams already on Vault/Teleport may prefer to bolt masking views onto those.
