# Example policies

Fictional names only. Never put real PHI, PII, credentials, or keys here.

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
        row_filters:
          - "REGION = 'west'"
```

`--apply` reads column types from `INFORMATION_SCHEMA.COLUMNS`, builds a secure view `FROM db.s.t AS "SRC"`, and re-emits filters as `"SRC"."COL"`. Same five masks as Postgres. Hashes are not designed to be joinable with Postgres hashes (different HMAC output encoding). Sweep every 1 minute. Details: [CLI](../docs/cli.md), [operations](../docs/operations.md#warehouses-v060).
