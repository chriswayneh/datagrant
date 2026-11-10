# Roadmap

datagrant grows in small, reviewed units. Each unit is one pull request with tests and docs. This page is the summary; the planning history is in [roadmap/](roadmap/) and [aidlc-docs/](aidlc-docs/).

## Milestones

| Version | Theme | Status |
| --- | --- | :---: |
| v0.1.0 | Expiring, masked, receipted Postgres access from the CLI | ✅ Released |
| v0.2.0 | Tighter privacy controls and off-host evidence | ✅ Released |
| v0.3.0 | Real identity | ✅ Released |
| v0.4.0 | Approvals and policy limits | Design |
| v0.5.0+ | More warehouses | Planned |

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

## v0.4.0: design

| Item | What | Status |
| --- | --- | :---: |
| Approvals and policy limits | Policy-wide N-of-M quorum (cap 8), optional distinct-groups SoD on the table's `allowed_groups`, policy-capped pending TTL, `max_columns`, max concurrent grants, denial/expiry receipts on `--apply`. No break-glass (emergency path is a reviewed policy edit to `auto`). Construction is a sequence of small PRs after this design is approved. Design: [docs/design/approvals-policy-limits.md](docs/design/approvals-policy-limits.md). | Design |

## Next

| Item | Why | Target |
| --- | --- | :---: |
| Approvals and policy limits | Stronger two-person control and policy caps on top of v0.3.0 identity. See the v0.4.0 design above. | v0.4.0 |
| Snowflake and BigQuery | The same request, mask, expire and receipt model on other warehouses. | v0.5.0+ |

Ideas and priorities may change. Open an issue to discuss one.
