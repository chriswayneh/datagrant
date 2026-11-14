# Roadmap

datagrant grows in small, reviewed units. Each unit is one pull request with tests and docs. This page is the summary; the planning history is in [roadmap/](roadmap/) and [aidlc-docs/](aidlc-docs/).

## Milestones

| Version | Theme | Status |
| --- | --- | :---: |
| v0.1.0 | Expiring, masked, receipted Postgres access from the CLI | ✅ Released |
| v0.2.0 | Tighter privacy controls and off-host evidence | ✅ Released |
| v0.3.0 | Real identity | ✅ Released |
| v0.4.0 | Approvals and policy limits | ✅ Released |
| v0.5.0 | Ops hardening | ✅ Released |
| v0.6.0 | Warehouses | ✅ Released |
| v0.7.0+ | More warehouses (BigQuery) | Planned |

## v0.1.0: done

| Unit | What | Status |
| --- | --- | :---: |
| U1 | Policy loader, validation, deny-by-default evaluator | ✅ |
| U2 | Postgres grant engine: scoped view, expiring role, state, row filters | ✅ |
| U3 | Column masking: redact, null, partial, keyed hash | ✅ |
| U4 | Revoke and expiry sweep with session termination | ✅ |
| U5 | Signed, hash-chained receipts and verify | ✅ |
| U6 | CLI with dry-run default, two-person approval, exit codes | ✅ |
| U7 | One-command demo, run in CI | ✅ |
| U8 | Docs and release prep | ✅ |

## v0.2.0: done

| Item | What | Status |
| --- | --- | :---: |
| Per-dataset hash scope | Stop same-key hashes from linking values across datasets (`hash_scope`). Changes hash outputs from v0.1.0. | ✅ |
| `filter_columns` | Let a row filter use a column without exposing it in the view. | ✅ |
| External receipt sink | Webhook and `file://` sinks, outbox, `receipts push`, `receipts verify --sink`. Design: [docs/design/receipt-sink.md](docs/design/receipt-sink.md). | ✅ |

## v0.3.0: done

| Item | What | Status |
| --- | --- | :---: |
| OIDC identity | Authenticate requesters and approvers so two-person approval is enforced, not just recorded. `policy.identity`, `--oidc-token-file` / `$DATAGRANT_OIDC_TOKEN`, mode parity and `(iss, sub)` checks. Design: [docs/design/oidc-identity.md](docs/design/oidc-identity.md). Demo: [docs/demo-oidc.md](docs/demo-oidc.md). | ✅ |

## v0.4.0: done

| Item | What | Status |
| --- | --- | :---: |
| Approvals and policy limits | Policy-wide N-of-M quorum (cap 8); `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty; policy-capped pending TTL, `max_columns`, max concurrent grants, denial/expiry receipts on `--apply`. No break-glass (emergency path is a reviewed policy edit to `auto`). Design: [docs/design/approvals-policy-limits.md](docs/design/approvals-policy-limits.md). | ✅ |

## v0.5.0: done

| Item | What | Status |
| --- | --- | :---: |
| Ops hardening | Session `pg_advisory_lock` on mutating `--apply` (unlock in `finally`); `datagrant doctor`; optional `strict_preflight` (access-creating only); receipt-log 0600; optional `strict_policy_permissions`; `SET LOCAL log_statement` when the admin can SET it. No warehouses, rate limits, `max_rows`, or break-glass. Design: [docs/design/ops-hardening.md](docs/design/ops-hardening.md). | ✅ |

## v0.6.0: done

| Item | What | Status |
| --- | --- | :---: |
| Warehouses | Same request, mask, expire and receipt model on Snowflake first (per-grant `TYPE=SERVICE` user, key pair shown once, secure view, local receipts). BigQuery later. Postgres CLI unchanged. Design approved (PR #47 at `0449a0b`; picks 1B/2B/3A/4A/5B/6B/7B). Construction PRs #48 to #52: policy `engine` and Snowflake `--apply` routing; grant engine; revoke and sweep (atomic claims, 10-minute issuing/enabling grace); grant/approve `--apply` and concurrent cap across Snowflake datasets; masks and catalog (five mask names, type inspect, `"SRC"`-qualified filters so `IS NULL` on a `null`-masked column uses the base column). Hashes are not designed to be joinable with Postgres hashes (different HMAC output encoding). Design: [docs/design/warehouses.md](docs/design/warehouses.md). | ✅ |

## Next

| Item | Why | Target |
| --- | --- | :---: |
| BigQuery | The same model on BigQuery (IAM / authorized views, not a password user). Design: [docs/design/bigquery.md](docs/design/bigquery.md) (**pending approval**). | v0.7.0+ |

Ideas and priorities may change. Open an issue to discuss one.
