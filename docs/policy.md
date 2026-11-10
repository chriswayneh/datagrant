# Policy reference

A policy is one YAML file (`--policy` or `$DATAGRANT_POLICY`). It is loaded with a strict safe loader. Unknown keys, duplicate keys and wrong types are errors. Files are capped at 1 MB. Evaluation is **deny by default**: anything not allowed explicitly is refused, and every denial gives its reasons.

Validate it offline with `datagrant policy check FILE` (exit 0 valid, 1 invalid).

## Top level

| Key | Required | Meaning |
| --- | :---: | --- |
| `version` | yes | Must be `1`. |
| `approval` | yes | `auto` grants immediately when allowed. `two-person` creates a pending request that someone else must approve. |
| `approvers` | two-person only | List of group names whose members can approve. Required when `approval: two-person`. |
| `approvals_required` | no | Policy-wide only. Integer `1`..`8`. How many distinct approvers must approve a pending request before it is issued. Omit it, or set `1`, for v0.3.0 one-approver behavior. Illegal when `approval` is `auto`. A dataset- or table-level `approvals_required` is an unknown-key error. The same person voting twice counts once (idempotent). The requester still cannot approve their own request. |
| `max_duration` | yes | Policy-wide cap on any grant. |
| `pending_ttl` | no | Cap on an explicit `request --pending-ttl` in `two-person` mode (`1m`..`7d`, same duration grammar as grants). Omit it for v0.3.0 behavior. When set, a longer **explicit** `--pending-ttl` is a usage error (exit 2) before any database write. If the flag is omitted, the pending lifetime is `min(24h, policy.pending_ttl)`. The cap is not applied when `approval` is `auto`. |
| `max_concurrent_grants` | no | Positive integer. Cap on how many live grants one requester may hold. Count is `status = 'active' AND expires_at > now()` (revoked grants and grants past `expires_at`, swept or not, do not count). Omit it for no cap. The effective cap for a request is the minimum of this value and the dataset's `max_concurrent_grants` among those that are set. |
| `groups` | yes | Map of group name to a list of user names (1 to 256 printable ASCII characters without spaces). Email-style names (containing `@`) fold ASCII `A-Z` to `a-z`; duplicate members in a group or conflicting spellings across groups are policy errors. Empty lists are allowed: in `identity.mode: oidc`, membership can come only from `identity.group_map`. |
| `datasets` | yes | List of datasets (see below). |
| `identity` | no | How `request` and `approve` name the caller. Omit it, or set `mode: local`, for OS/`--as-user` names. Set `mode: oidc` to require a verified ID token. See [Identity](#identity). |

## Datasets

| Key | Meaning |
| --- | --- |
| `name` | Dataset name used with `request --dataset`. |
| `database` | Postgres database name. A grant is refused if the DSN connects to a different database. |
| `tables` | List of tables. |
| `hash_scope` | Optional. Name of the hash scope (`[A-Za-z0-9_.-]`, up to 64 characters). Defaults to the dataset name, so each dataset hashes differently. Give two datasets the same `hash_scope` only when their hashes should be joinable. |
| `max_concurrent_grants` | Optional positive integer. Tighter of this and the policy-wide cap, if either is set. Count is the requester's live grants (`status = 'active' AND expires_at > now()`, all datasets). |

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
| `max_columns` | no | Positive integer. A request whose unique column count exceeds it is denied. It cannot exceed the size of `columns`. Omit it for no extra cap beyond the allow-list. |

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

See [`examples/policy.yaml`](../examples/policy.yaml) for a complete local-mode file, and [`examples/policy-oidc.yaml`](../examples/policy-oidc.yaml) for `identity.mode: oidc`.

## Identity

Optional. When omitted, datagrant behaves as v0.2.0: the caller is the OS user, or `--as-user`. That records a name; it does not prove one.

`datagrant policy check FILE` validates the block offline (no IdP, no database). Unknown keys under `identity` are errors, matching the rest of the file.

| Key | Required | Meaning |
| --- | :---: | --- |
| `mode` | no | `local` (default) or `oidc`. |
| `issuer` | oidc | Exact `iss` match. `https://` URL with a host, no credentials, query or fragment. Trailing slash is kept because comparison is byte-for-byte. Plain `http://127.0.0.1` and `http://localhost` are refused unless `DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1` (test-only; `policy check` then warns). Other `http://` URLs are always refused. |
| `audience` | oidc | Non-empty string, or non-empty list of strings. Token `aud` must equal one of these (string) or intersect the list. If `aud` has several values, `azp` is required; whenever `azp` is present it must also be in this list. |
| `algorithms` | no | Non-empty subset of `RS256`, `ES256`, `EdDSA`. Default: all three. `none`, `HS*`, other `RS*`/`PS*`, and `ES384`/`ES512` are policy errors. |
| `username_claim` | no | Claim that becomes the requester or approver name. Default `sub`. Must match `[A-Za-z0-9_.-]{1,64}`. When this is `email`, verification also requires `email_verified` to be boolean `true` (the string `"true"` is refused). |
| `groups_claim` | if mapping | Claim holding IdP group strings. Required when `allowed_groups` or `group_map` is set. Missing claim at runtime means an empty group list. A non-list value is an error. |
| `allowed_groups` | no | Optional admission gate on **raw** IdP group names. The token must include at least one listed value or authentication fails. This does not grant a policy group. |
| `group_map` | no | Map of `{idp-group: policy-group}`. Off/empty by default. Every target must exist in `policy.groups`. Unmapped IdP groups, including ones whose names match a policy group, grant nothing. |
| `max_token_age` | no | Max age of `iat`, `1m`..`24h`. Default `15m`. These identity durations accept `s`/`m`/`h`/`d` (unlike grant `--duration`, which has no seconds). |
| `clock_skew` | no | `0s`..`5m`. Default `60s`. |
| `jwks_cache_ttl` | no | JWKS disk cache TTL, `0s`..`24h`. Default `5m`. `0s` fetches every time. |

In `local` mode, any other `identity.*` key is a policy error, so a half-written OIDC block cannot silently fall back.

Effective policy groups for a verified caller are:

```text
policy.groups_of(username)  union  { group_map[g] for each IdP group g that is a key in group_map }
```

`groups_of` is the static `policy.groups` membership of the verified username (email-style names folded ASCII `A-Z` to `a-z`). Mapped groups are extra. Static membership still works if you list the verified name in `policy.groups`.

datagrant does not obtain tokens. The IdP issues an ID token; the caller presents it. See [CLI: OIDC identity](cli.md#oidc-identity) and the [OIDC demo](demo-oidc.md).
