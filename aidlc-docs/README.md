# AI-DLC artifacts

datagrant follows the [AWS AI-Driven Development Life Cycle](https://github.com/awslabs/aidlc-workflows): Inception (what and why), Construction (how), Operations (run it). Each stage ends with a human approval gate.

The product is v0.6.1, ready, release pending ([release notes](../docs/release-notes/v0.6.1.md)). The latest published release is [v0.6.0](https://github.com/chriswayneh/datagrant/releases/tag/v0.6.0). M4 Snowflake warehouses shipped in that tag; v0.6.1 patches Snowflake setup (`SHA2_HMAC`). M5 BigQuery is under construction. See the [product README](../README.md) and [ROADMAP.md](../ROADMAP.md).

| Stage | Folder | Roadmap | Gate |
| --- | --- | --- | --- |
| Inception | [inception/](inception/) | v0.1.0 | Maintainer approves vision, requirements, stories, units |
| Construction | [construction/](construction/) | v0.2.0 to v0.6.0 | Maintainer approves design and NFRs per unit before code; test plan before release |
| Operations | [operations/](operations/) | v0.9.0 to v1.0.0 | Maintainer approves runbook and threat model |

- [aidlc-state.md](aidlc-state.md) tracks the phase and approval gates.
- [audit.md](audit.md) is the append-only log of decisions and approvals.
- M2 / v0.4.0 (approvals and policy limits): released 2026-11-10. Design: [docs/design/approvals-policy-limits.md](../docs/design/approvals-policy-limits.md).
- M3 / v0.5.0 (ops hardening): released 2026-11-11. Design: [docs/design/ops-hardening.md](../docs/design/ops-hardening.md).
- M4 / v0.6.0 (warehouses): released 2026-11-14. Snowflake: `engine: snowflake`, key-pair-only `$DATAGRANT_SNOWFLAKE_DSN`, per-grant `TYPE=SERVICE` user, secure view, `request` / `approve` / `revoke` / `sweep`, five masks, `INFORMATION_SCHEMA` catalog inspect, `"SRC"`-qualified row filters. Design: [docs/design/warehouses.md](../docs/design/warehouses.md). Authoritative pages: [CLI](../docs/cli.md), [policy](../docs/policy.md), [operations](../docs/operations.md#warehouses-v060).
- M5 / v0.7.0+ (BigQuery): [step 4](https://github.com/chriswayneh/datagrant/pull/62) merged with mocked revoke and sweep; [step 5 of 7](https://github.com/chriswayneh/datagrant/pull/63) is in draft with adapter and approval work. BigQuery `--apply` remains disabled. [Design](../docs/design/bigquery.md) approved 2026-11-14 4:51 PM CT (picks 1B through 11B).

Working rules: see [AGENTS.md](../AGENTS.md).

Rules: propose, then wait for approval; record every approval in `audit.md`; never skip a gate.
