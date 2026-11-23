# Roadmap

datagrant gives people short-lived, masked, receipted access to sensitive data, with approval, and takes it away on its own. It grows in small, reviewed pull requests with tests and docs. The planning history is in [roadmap/](roadmap/) and [aidlc-docs/](aidlc-docs/).

**Where we are:** alpha. The core flow works on Postgres, Snowflake, and BigQuery. [v0.8.0 is released](https://github.com/chriswayneh/datagrant/releases/tag/v0.8.0). The policy file and receipt format can still change before 1.0.

## At a glance

| Stage | Version | Theme | Status |
| --- | --- | --- | :---: |
| Alpha: core | v0.1.0 to v0.6.0 | Expiring, masked, receipted access on Postgres and Snowflake, real identity, two-person approval, ops hardening | ✅ Released |
| Alpha: core | v0.6.1 | Patch: Snowflake setup fix | ✅ Released |
| Alpha: core | v0.7.0 | BigQuery | ✅ Released |
| Alpha: compliance | v0.8.0 | PCI pack | ✅ Released. [Release notes](docs/release-notes/v0.8.0.md) |
| Beta | v0.9.0 | Ready for outside teams | Planned |
| Stable | v1.0.0 | Stable formats and a compatibility promise | Planned |

## Alpha: building the core

### v0.6.1: Snowflake patch (released)

| Item | What |
| --- | --- |
| Setup fix | v0.6.0 Snowflake setup called `SHA2_HMAC`, which Snowflake does not provide, so `CREATE FUNCTION HASH_HMAC` could fail. [v0.6.1](https://github.com/chriswayneh/datagrant/releases/tag/v0.6.1) ships the Python HMAC UDF ([#61](https://github.com/chriswayneh/datagrant/pull/61)). Use v0.6.1 or later for Snowflake. |
| Known-issue note | README and [v0.6.0 notes](docs/release-notes/v0.6.0.md) point to v0.6.1 as the fix. |

### v0.7.0: BigQuery (released)

The same request, mask, expire and receipt flow on Google BigQuery: a per-grant authorized view plus an expiring IAM permission on the requester's own Google login, Google default credentials only (key files refused), and revoke that fails closed. Design: [docs/design/bigquery.md](docs/design/bigquery.md). Notes: [docs/release-notes/v0.7.0.md](docs/release-notes/v0.7.0.md). Mock- and CI-tested; a live GCP test was not run.

| Step | What | Status |
| --- | --- | :---: |
| 1 | Design (11 approved picks) | ✅ |
| 2 | Policy engine and credential routing | ✅ |
| 3 | View SQL, grant order, IAM bind and unbind | ✅ |
| 4 | Revoke and sweep | ✅ |
| 5 | Adapter and approval groundwork ([#63](https://github.com/chriswayneh/datagrant/pull/63)) | ✅ |
| 6 | CLI request and approval routing, concurrent-grant caps, recovery | ✅ |
| 7 | Turn on `--apply` for BigQuery, hash setup, docs and 0.7.0 prep | ✅ |

## Alpha: compliance

### v0.8.0: PCI pack (released)

Help teams that hold card data show that access to it is limited, approved, masked and recorded. datagrant **supports** PCI DSS controls. It does not make anyone PCI compliant on its own, and an assessor still decides.

| Item | What | PCI DSS v4.0.1 |
| --- | --- | --- |
| Card-number mask | A built-in mask that shows at most the first 6 and last 4 digits of a card number (PAN). | Req. 3.4.1 (mask PAN when displayed) |
| Sample cardholder-data policy | A ready-to-copy policy for a cardholder-data table: deny by default, least columns, short expiry, two-person approval. | Req. 7 (restrict access by need to know) |
| Identity and approval mapping | Docs showing how signed-in requesters and approvers, and distinct approvers, map to unique IDs and approval. | Req. 8 (identify users and authenticate access) |
| Evidence report | Turn signed receipts into a readable report of who requested and approved a grant, its scope and expiry, and any recorded revocation. | Req. 10 (log and monitor access), access reviews |
| Mapping doc | [PCI DSS guide](docs/compliance/pci.md): each datagrant feature, the requirement it supports, and what stays the customer's job. | All of the above |

## Beta: ready for outside teams

### v0.9.0

| Item | What |
| --- | --- |
| Feature freeze | No new engines or major features; bugs, docs and hardening only. |
| Live acceptance tests | Run the full flow against real Snowflake and BigQuery test accounts, not only mocks. |
| Easy install | Publish to PyPI and a container image. |
| Operator guide | Setup, day-two operations, backups, key rotation, troubleshooting. |
| Upgrade path | Tested upgrades between versions, with migration notes for any policy or state change. |
| Access review report | A periodic report of every grant in a window for reviewers and auditors. |

## Stable

### v1.0.0

| Item | What |
| --- | --- |
| Stable formats | The policy file and receipt format are locked. No breaking changes without a major version. |
| External security review | An independent review of the grant, revoke and receipt paths, with findings fixed. |
| Complete docs | Every command, policy field and engine documented and tested. |

## Later ideas

No dates yet. Open an issue to discuss one.

- More warehouses, such as Databricks and Redshift.
- Approvals in Slack or a ticketing tool.
- More compliance packs, such as SOC 2.

## Shipped history

### v0.1.0: done

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

### v0.2.0: done

| Item | What | Status |
| --- | --- | :---: |
| Per-dataset hash scope | Stop same-key hashes from linking values across datasets (`hash_scope`). Changes hash outputs from v0.1.0. | ✅ |
| `filter_columns` | Let a row filter use a column without exposing it in the view. | ✅ |
| External receipt sink | Webhook and `file://` sinks, outbox, `receipts push`, `receipts verify --sink`. Design: [docs/design/receipt-sink.md](docs/design/receipt-sink.md). | ✅ |

### v0.3.0: done

| Item | What | Status |
| --- | --- | :---: |
| OIDC identity | Authenticate requesters and approvers so two-person approval is enforced, not just recorded. `policy.identity`, `--oidc-token-file` / `$DATAGRANT_OIDC_TOKEN`, mode parity and `(iss, sub)` checks. Design: [docs/design/oidc-identity.md](docs/design/oidc-identity.md). Demo: [docs/demo-oidc.md](docs/demo-oidc.md). | ✅ |

### v0.4.0: done

| Item | What | Status |
| --- | --- | :---: |
| Approvals and policy limits | Policy-wide N-of-M quorum (cap 8); `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty; policy-capped pending TTL, `max_columns`, max concurrent grants, denial/expiry receipts on `--apply`. No break-glass (emergency path is a reviewed policy edit to `auto`). Design: [docs/design/approvals-policy-limits.md](docs/design/approvals-policy-limits.md). | ✅ |

### v0.5.0: done

| Item | What | Status |
| --- | --- | :---: |
| Ops hardening | Session `pg_advisory_lock` on mutating `--apply` (unlock in `finally`); `datagrant doctor`; optional `strict_preflight` (access-creating only); receipt-log 0600; optional `strict_policy_permissions`; `SET LOCAL log_statement` when the admin can SET it. No warehouses, rate limits, `max_rows`, or break-glass. Design: [docs/design/ops-hardening.md](docs/design/ops-hardening.md). | ✅ |

### v0.6.0: done

| Item | What | Status |
| --- | --- | :---: |
| Warehouses | Same request, mask, expire and receipt model on Snowflake first (per-grant `TYPE=SERVICE` user, key pair shown once, secure view, local receipts). BigQuery later. Postgres CLI unchanged. Design approved (PR #47 at `0449a0b`; picks 1B/2B/3A/4A/5B/6B/7B). Construction PRs #48 to #52: policy `engine` and Snowflake `--apply` routing; grant engine; revoke and sweep (atomic claims, 10-minute issuing/enabling grace); grant/approve `--apply` and concurrent cap across Snowflake datasets; masks and catalog (five mask names, type inspect, `"SRC"`-qualified filters so `IS NULL` on a `null`-masked column uses the base column). BigQuery and Postgres hashes of the same value under the same `hash_scope` are identical, and Snowflake's are the same value in uppercase. Use distinct `hash_scope` values per engine when hashes must not link. Design: [docs/design/warehouses.md](docs/design/warehouses.md). | ✅ |

### v0.6.1: done

| Item | What | Status |
| --- | --- | :---: |
| Snowflake HMAC patch | Replace the v0.6.0 `SHA2_HMAC` setup call with a secure Python 3.12 UDF. Tag `v0.6.1` on `release/0.6.x`. Notes: [docs/release-notes/v0.6.1.md](docs/release-notes/v0.6.1.md). | ✅ |

### v0.7.0: released

| Item | What | Status |
| --- | --- | :---: |
| BigQuery | Same request, mask, expire and receipt model on BigQuery (authorized view, IAM bind to a Google principal, ADC only). `datagrant setup bigquery`, hash-master load job, source-project catalog inspect. Notes: [docs/release-notes/v0.7.0.md](docs/release-notes/v0.7.0.md). | ✅ |

Ideas and priorities may change. Open an issue to discuss one.
