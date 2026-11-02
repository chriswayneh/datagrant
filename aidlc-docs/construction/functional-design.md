# Functional design

## U1 — Policy loader and evaluator

**Status:** In progress (Construction start approved 2026-11-02 5:26 PM CT; see ../audit.md). Module: `src/datagrant/policy.py`. Example: `examples/policy.yaml`.

### Policy schema (version 1, YAML via a strict SafeLoader subclass, ≤1 MB; rejects anchors/aliases, duplicate keys, and deep nesting)
| Key | Type | Notes |
| --- | --- | --- |
| `version` | int | Must be `1` |
| `approval` | `auto` \| `two-person` | Default `auto` |
| `max_duration` | `30m`/`4h`/`1d` | Policy-wide cap |
| `groups` | map group → [requesters] | Requester groups |
| `datasets[]` | `name`, `database`, `tables[]` | Unique names; Postgres identifier checks |
| `tables[]` | `name` (`schema.table`), `allowed_groups`, `columns` (col → mask), `row_filters[]`, `require_row_filter`, `max_duration` | Table cap ≤ policy cap; inherits it if absent |

Masks: `passthrough`, `redact`, `hash`, `partial`, `null`. Unknown keys are errors (catches typos).

### Evaluation (`evaluate(policy, request) -> Decision`)
Deny by default; all failing checks are reported: dataset/table exists, requester in an allowed group, columns allowed and unique, purpose present, 0 < duration ≤ table max, row filter required/exactly one of the allowlisted filters. Allowed decisions carry the per-column mask plan, approval mode, and policy SHA-256 (for receipts).

### Errors
`PolicyError` with a path like `policy.datasets[0].tables[1].columns.ssn`. No data values are read or logged.

### Out of U1
SQL generation, filter parsing (filters are matched against an allowlist only; U2 validates/quotes them), CLI wiring (U6).
