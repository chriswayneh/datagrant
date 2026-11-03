# Roadmap

datagrant grows in small, reviewed units. Each unit is one pull request with tests and docs. This page is the summary; the planning history is in [roadmap/](roadmap/) and [aidlc-docs/](aidlc-docs/).

## Milestones

| Version | Theme | Status |
| --- | --- | :---: |
| v0.1.0 | Expiring, masked, receipted Postgres access from the CLI | ✅ Built, not yet released |
| v0.2.0 | Tighter privacy controls | Planned |
| v0.3.0 | Off-host evidence | Planned |
| v0.4.0 | Real identity | Planned |
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

## Next

| Item | Why | Target |
| --- | --- | :---: |
| Per-dataset hash scope | Stop same-key hashes from linking values across datasets and grants. | v0.2.0 |
| `filter_columns` | Let a row filter use a column without exposing it in the view. | v0.2.0 |
| External receipt sink | Ship receipts off the host (object store with retention, SIEM) so tail truncation is caught without a manually recorded head. | v0.3.0 |
| OIDC identity | Authenticate requesters and approvers so two-person approval is enforced, not just recorded. | v0.4.0 |
| Snowflake and BigQuery | The same request, mask, expire and receipt model on other warehouses. | v0.5.0+ |

Ideas and priorities may change. Open an issue to discuss one.
