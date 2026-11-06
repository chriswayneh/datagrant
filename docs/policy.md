# Policy reference

A policy is one YAML file (`--policy` or `$DATAGRANT_POLICY`). It is loaded with a strict safe loader. Unknown keys, duplicate keys and wrong types are errors. Files are capped at 1 MB. Evaluation is **deny by default**: anything not allowed explicitly is refused, and every denial gives its reasons.

Validate it offline with `datagrant policy check FILE` (exit 0 valid, 1 invalid).

## Top level

| Key | Required | Meaning |
| --- | :---: | --- |
| `version` | yes | Must be `1`. |
| `approval` | yes | `auto` grants immediately when allowed. `two-person` creates a pending request that someone else must approve. |
| `approvers` | two-person only | List of group names whose members can approve. Required when `approval: two-person`. |
| `max_duration` | yes | Policy-wide cap on any grant. |
| `groups` | yes | Map of group name to a list of user names. Email-style names (containing `@`) compare case-insensitively. |
| `datasets` | yes | List of datasets (see below). |

## Datasets

| Key | Meaning |
| --- | --- |
| `name` | Dataset name used with `request --dataset`. |
| `database` | Postgres database name. A grant is refused if the DSN connects to a different database. |
| `tables` | List of tables. |
| `hash_scope` | Optional. Name of the hash scope (`[A-Za-z0-9_.-]`, up to 64 characters). Defaults to the dataset name, so each dataset hashes differently. Give two datasets the same `hash_scope` only when their hashes should be joinable. |

## Tables

| Key | Required | Meaning |
| --- | :---: | --- |
| `name` | yes | `schema.table`. Both parts are plain identifiers (`[A-Za-z_][A-Za-z0-9_]*`, up to 63 characters). |
| `allowed_groups` | yes | Groups whose members may request this table. |
| `columns` | yes | Map of column to mask. Only listed columns can be requested. |
| `filter_columns` | no | Columns that row filters may use but that are never in the view and can't be requested. Each must be used by a row filter and must not also be in `columns`. |
| `row_filters` | no | Allowed row filters. A request's `--row-filter` must exactly match one entry. |
| `require_row_filter` | no | `true` means a request without a row filter is denied. Needs at least one `row_filters` entry. |
| `max_duration` | no | Per-table cap. It may not exceed the policy-wide `max_duration`. |

## Durations

`<n>m`, `<n>h` or `<n>d`, where n is a positive integer (for example `30m`, `4h`, `1d`). Seconds aren't supported.

## Masks

| Mask | Grantee sees |
| --- | --- |
| `passthrough` | The real value. |
| `redact` | The constant `[REDACTED]`. |
| `null` | NULL, cast to the column's type. |
| `partial` | Asterisks plus the last 4 characters. Values shorter than 8 characters are fully masked. |
| `hash` | A hex HMAC-SHA256 of the value under a key derived from the local hash key and the dataset's `hash_scope`. It needs `pgcrypto`, and fails closed without it or without the key. Equal inputs give equal outputs within one hash scope (see [linkability](security.md#known-limits)). |

Column types are read from the catalog when the grant is created.

## Row filters

```text
expr    := term ("OR" term)*
term    := factor ("AND" factor)*
factor  := "(" expr ")" | ident op literal | ident "IS" ["NOT"] "NULL"
op      := = | <> | != | < | <= | > | >=
literal := 'string' ('' escapes) | integer | decimal | TRUE | FALSE
```

Keywords are case-insensitive. The filter is at most 1000 characters and nests at most 16 levels deep. Every identifier must be in the table's `columns` or `filter_columns`; anything else is a policy error. The filter is parsed and re-emitted with quoted identifiers and literals, so it is never interpolated. A column used only in `filter_columns` is not in the view (see [security](security.md)).

```yaml
- name: public.visits
  allowed_groups: [analysts]
  columns: {visit_id: passthrough, patient_id: hash}
  filter_columns: [region]          # filters on region, never shows it
  row_filters: ["region = 'west'"]
  require_row_filter: true
```

See [`examples/policy.yaml`](../examples/policy.yaml) for a complete file.
