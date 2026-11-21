# Example policies

Fictional names only. Never put real PHI, PII, credentials, or keys here.

These examples cover released engines (Postgres, Snowflake, and BigQuery in v0.7.0). See the [design](../docs/design/bigquery.md) and [operations](../docs/operations.md#bigquery-v070).

| File | Identity | Engine |
| --- | --- | --- |
| [policy.yaml](policy.yaml) | local (OS user / `--as-user`) | Postgres (omit `engine`) |
| [policy-oidc.yaml](policy-oidc.yaml) | `identity.mode: oidc` | Postgres |

Check a file with `datagrant policy check examples/policy.yaml` (exit 0 valid, 1 invalid). See the [policy reference](../docs/policy.md) and [OIDC demo](../docs/demo-oidc.md).

## Snowflake (v0.6.0)

Add a dataset with `engine: snowflake`. Install `pip install '.[snowflake]'` from a checkout of the v0.6.0 tag. Set `$DATAGRANT_SNOWFLAKE_DSN` to a service user with `private_key_file` (key-pair only; password auth is refused). `request` / `approve` / `revoke` / `sweep` / `grant list` take `--snowflake-dsn` when the env var is unset.

```yaml
  - name: snow_clinic
    engine: snowflake
    database: CLINIC_DB
    schema: PUBLIC
    tables:
      - name: PUBLIC.PATIENTS
        allowed_groups: [ml-team]
        columns:
          PATIENT_ID: passthrough
          SSN: hash
        filter_columns: [REGION]
        row_filters:
          - "REGION = 'west'"
```

`--apply` reads column types from `INFORMATION_SCHEMA.COLUMNS`, builds a secure view `FROM db.s.t AS "SRC"`, and re-emits filters as `"SRC"."COL"`. Same five masks as Postgres. BigQuery and Postgres hashes of the same value under the same `hash_scope` are identical, and Snowflake's are the same value in uppercase. Use distinct `hash_scope` values per engine when hashes must not link. Sweep every 1 minute. Details: [CLI](../docs/cli.md), [operations](../docs/operations.md#warehouses-v060).

## BigQuery (v0.7.0)

Add a dataset with `engine: bigquery`. Install `pip install '.[bigquery]'` from a checkout of the v0.7.0 tag. Set `$DATAGRANT_BIGQUERY_PROJECT` and use ADC (JSON keys refused). Run `datagrant setup bigquery --apply` once against an operator-only `datagrant` dataset. Prefer a dedicated hash project: project-level BigQuery data roles are key-equivalent.

```yaml
  - name: bq_clinic
    engine: bigquery
    database: source-proj
    schema: clinic_ds
    location: US
    tables:
      - name: clinic_ds.patients
        allowed_groups: [ml-team]
        columns:
          patient_id: passthrough
          ssn: hash
        filter_columns: [region]
        row_filters:
          - "region = 'west'"
```

`--apply` inspects `INFORMATION_SCHEMA.COLUMNS` in the source project, builds an authorized view with `` `SRC` ``, and binds IAM to the Google principal from `policy.identity.google_principals`. Same five masks as Postgres. BigQuery and Postgres hashes of the same value under the same `hash_scope` are identical, and Snowflake's are the same value in uppercase. Use distinct `hash_scope` values per engine when hashes must not link. Sweep every 1 minute. Details: [CLI](../docs/cli.md), [operations](../docs/operations.md#bigquery-v070).
