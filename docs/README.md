# datagrant docs

Released features are documented for [v0.7.0](https://github.com/chriswayneh/datagrant/releases/tag/v0.7.0). The product README is at the [repo root](../README.md).

| Page | What it covers |
| --- | --- |
| [CLI](cli.md) | Flags, exit codes, Snowflake DSN, BigQuery project / ADC |
| [Policy](policy.md) | Deny-by-default YAML, `engine: snowflake` / `engine: bigquery`, masks, row filters |
| [Security](security.md) | Trust boundaries and known limits |
| [Operations](operations.md) | Runbook pointers, [Snowflake](operations.md#warehouses-v060), [BigQuery](operations.md#bigquery-v070), ops hardening |
| [Demo](demo.md) | Local Postgres demo (`make demo`) |
| [OIDC demo](demo-oidc.md) | Request and approve with synthetic tokens |
| [v0.7.0 notes](release-notes/v0.7.0.md) | BigQuery warehouse support |
| [v0.6.1 notes](release-notes/v0.6.1.md) | Snowflake HMAC patch |
| [v0.6.0 notes](release-notes/v0.6.0.md) | Snowflake warehouse support |

Design notes: [BigQuery](design/bigquery.md) (M5 / v0.7.0), [warehouses](design/warehouses.md) (M4 / v0.6.0, Snowflake shipped), [ops hardening](design/ops-hardening.md), [approvals](design/approvals-policy-limits.md), [OIDC](design/oidc-identity.md), [receipt sink](design/receipt-sink.md).

Example policies live in [examples/](../examples/). Changelog and roadmap: [CHANGELOG.md](../CHANGELOG.md), [ROADMAP.md](../ROADMAP.md). The upcoming v0.8.0 [PCI DSS guide](compliance/pci.md) maps the support pack to selected controls.
