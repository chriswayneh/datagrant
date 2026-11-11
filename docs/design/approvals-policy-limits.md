# Design: approvals and policy limits (v0.4.0 / M2)

Status: implemented in v0.4.0 (PRs #34 to #38). Release pending, not tagged. Differences from this proposal: the Nth vote is not persisted until `apply_plan`'s transaction (`persist_if_final` is false); `claim_request` merges only the caller's new vote with the locked row and returns the counted set; if the locked counted names do not match `plan.facts.approvers`, apply fails closed and the request stays pending; votes are stamped with `policy.sha256`, OIDC `iss`, and `mapped_groups`; live-grant counting uses `status = 'active' AND expires_at > now()`; a failed `approval_recorded` write removes that caller's vote; omitted `--pending-ttl` uses `min(24h, policy.pending_ttl)`. The [policy](../policy.md) and [CLI](../cli.md) pages are authoritative. Roadmap: [ROADMAP.md](../../ROADMAP.md).

Grounded in the v0.3.0 code on `main` (`src/datagrant/policy.py`, `cli.py`, `pg/requests.py`, `pg/grant.py`, `receipt.py`).

## Goal

v0.3.0 can prove *who* asked and who approved (OIDC), but the approval *workflow* is still one other person in a global `approvers` group, and most limits are duration plus column allow-lists. Operators who need four-eyes on a sensitive dataset, a cap on how many live grants one person holds, or evidence of denials have to invent that outside datagrant.

M2 tightens **approvals** and **policy-enforced limits** without turning datagrant into a ticket system or an identity provider. Default omitted keys keep v0.3.0 behavior so existing policies and receipt logs keep working.

Out of scope for M2: break-glass, other warehouses (v0.5.0+), a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, and anything that only the holder of `DATAGRANT_DSN` could bypass anyway without a real enforcement point. Emergency access in v0.4.0 is a reviewed policy edit to `approval: auto`.

## What is already true (do not rebuild)

| Behavior | Where | Keep as-is |
| --- | --- | --- |
| Policy-wide `max_duration` and optional per-table `max_duration` (table may not exceed policy) | `policy.py` | Already the duration cap. M2 does not add a second duration language. |
| `approval: auto \| two-person` and `approvers: [groups]` | policy top level | Mode stays policy-wide. No per-dataset `auto` vs `two-person` split (that would fork the CLI flow). |
| Self-approval refused by display name (casefold) and, in OIDC, `(iss, sub)` | `Policy.can_approve`, `cmd_approve` | Stays the floor. M2 may add an optional extra SoD check on top. |
| Pending request TTL via `--pending-ttl` (default `24h`); `sweep` marks stale rows `expired` and clears the verifier | `cli.py`, `pg/requests.py` | Exists, but the cap is only a CLI default. M2 adds a **policy** cap so a caller cannot pick `30d`. |
| Denials print reasons on stdout/JSON, exit 1 | `cmd_request`, `cmd_approve` | Keep the UX. M2 optionally **receipts** them on `--apply`. |
| Receipts version 1, events `issued`, `revoked`, `expired`, `revoke_failed`; `approvers` is already a list; additive `identity` / `approver_identities` | `receipt.py` | Stay on version 1. New events and fields are additive. Old logs must still verify. |
| Unknown policy keys are errors; `policy.version` must be `1` | `parse_policy` | New keys are optional. Omitting them is v0.3.0. Do not bump `policy.version`. |
| One approval wins in one transaction (`pending -> approved`) | `apply_plan(..., request_id=)` | Quorum generalizes this: the Nth distinct approval creates the grant. |

## Scope judgment

| Candidate | Verdict | Why |
| --- | --- | --- |
| N-of-M quorum (policy-wide only) | **Keep** | Real gap: today N is always 1. Policy-wide `approvals_required` is enough. No per-dataset override (Chris). |
| Per-dataset `approvals_required` | **Cut** | Chris: quorum is policy-wide only. |
| Sensitivity labels as a new taxonomy | **Cut** | Policy-wide quorum plus existing `max_duration` already express "this table is hotter". A label vocabulary would be unused config. |
| Separation of duties: optional `distinct-groups` | **Keep** (optional, default off) | Distinct-person is not enough when requester and approver share a group that is in the table's `allowed_groups`. Default off so current policies do not break. `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty. |
| `max_duration` as a new feature | **Already shipped** | Document only. |
| `max_columns` per table | **Keep** | Cheap. Stops "request every allowed column" when the allow-list is wide. Omit = unlimited (today). |
| `max_rows` at grant time | **Cut** | Chris: stays out. A `COUNT(*)` on the future view is racy, slow, and still not what the grantee will query. Row limits stay the job of `row_filters`. |
| `max_concurrent_grants` per principal | **Keep** | Count `datagrant.grants` rows with `status = 'active'` for that requester. Re-check at approve time. Same-transaction for `auto`. |
| Request rate limits (N per hour) | **Cut** | Chris: stays out. No daemon. Anyone with the admin DSN skips the CLI. A clock table would look like security and not be. |
| Policy-capped pending TTL | **Keep** | Promotes `--pending-ttl` to a policy max. CLI may only shorten. |
| Break-glass | **Cut** | Chris: not in v0.4.0. Emergency path is a reviewed policy edit to `approval: auto`. |
| Denial and expiry receipts | **Keep** (`--apply` only) | Chris: `--apply` only. Dry runs stay silent in the log. |
| `policy check` for the new keys | **Keep** | Same PR as schema. |
| v0.3.0 policy and receipt compatibility | **Keep** (hard requirement) | Omit new keys; old JSONL verifies. |
| Other warehouses | **Cut** (later) | Chris: v0.5.0+. |

## Policy configuration

`policy.version` stays `1`. Unknown keys remain errors. New keys are optional.

```yaml
version: 1
approval: two-person
approvers: [sec]
approvals_required: 2          # optional; default 1; only legal when approval is two-person; 1..8
separation_of_duties: none     # optional; none (default) or distinct-groups
pending_ttl: 24h               # optional; cap for --pending-ttl; default 24h if omitted
max_concurrent_grants: 3       # optional; omit = no cap
max_duration: 8h               # already required
groups:
  employees: [alice, carol, dave]
  ml-team: [alice]
  sec: [carol, dave]
datasets:
  - name: clinic
    database: clinicdb
    max_concurrent_grants: 1   # optional; tighter of policy-wide and dataset
    tables:
      - name: public.patients
        allowed_groups: [ml-team]
        max_columns: 1         # optional; must be <= len(columns); omit = no extra cap
        max_duration: 4h
        columns: { patient_id: hash, zip: partial }
```

Validation (`datagrant policy check` enforces all of this offline):

- `approvals_required` is policy-wide only. Positive integer, at most 8 (keeps the pending row small). Illegal when `approval: auto`. If omitted under `two-person`, it is `1` (today). A dataset-level `approvals_required` is an unknown-key error.
- `separation_of_duties`: `none` or `distinct-groups`. Unknown strings are errors. `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty. Groups come from static `policy.groups` plus `group_map`. It does not replace distinct-person / `(iss, sub)`.
- `pending_ttl` uses the existing duration grammar (`m`/`h`/`d`, no seconds), `1m`..`7d`. CLI `--pending-ttl` that exceeds it is a usage error (exit 2) before the database write.
- `max_concurrent_grants` is a positive integer, policy-wide and/or per dataset. Effective cap is the minimum of those that are set.
- `max_columns` is a positive integer per table. A request whose unique column count exceeds it is denied. It cannot exceed the size of `columns`.

## Evaluation and CLI

`evaluate()` grows new deny reasons; it stays deny-by-default and still returns every reason. Concurrent-grant counting needs a database read, so it lives in `cmd_request` / `cmd_approve` next to the existing catalog lookup, not inside pure `evaluate()`. The count is `status = 'active'` only (revoked and expired do not count). Two `auto` `--apply` races are accepted as a residual (CLI is one writer in the documented ops model); the insert stays in the existing grant transaction.

**Quorum (`approvals_required` > 1).** Policy-wide N. `datagrant.requests` gains an additive `approvals jsonb` (list of `{approver, at, identity}` objects) and keeps `status` in `pending|approved|expired`. Each `approve --apply`:

1. Re-runs today's identity, SoD, and policy checks.
2. Refuses a second vote from the same person (name and, in OIDC, `(iss, sub)`).
3. Appends the vote.
4. If `len(votes) < N`, leaves the row `pending`, prints how many remain, writes no grant, writes a receipt event `approval_recorded`.
5. If `len(votes) == N`, creates the grant in the same transaction as today, sets `status = approved`, copies all voters into `grants.approvers` and `approver_identities`.

Dry-run `approve` reports whether this caller would be vote 1 of N or the issuing vote.

**Denial and expiry receipts** only on `--apply` that actually refused (policy deny, SoD, quorum-ineligible, expired pending, concurrent cap) or on `sweep` when a pending request expires. Dry runs do not write. Signing key required; if a denial/not_approved/approval_recorded receipt cannot be written, exit 3 and **do not** create a pending row or grant (fail closed, same as issued).

## Receipt schema

`RECEIPT_VERSION` stays `1`. `verify()` already accepts any signed body with a valid chain, so old v0.3.0 lines keep verifying.

New events (writer allow-list only):

| Event | When | `grant_id` | Notes |
| --- | --- | --- | --- |
| `denied` | `request --apply` refused by policy or limits | omitted | `details.reasons` (list of strings), `details.phase: request` |
| `not_approved` | `approve --apply` refused | omitted; `details.request_id` set | `details.reasons`, `details.phase: approve` |
| `approval_recorded` | quorum vote that did not yet issue | omitted; `details.request_id` | `details.approvals_recorded`, `details.approvals_required` |
| `request_expired` | `sweep` expires a pending request | omitted; `details.request_id` | Evidence that a password was issued to the requester and never approved |

`approvers` and `approver_identities` already lists; quorum fills them with every voter. No break-glass fields.

Forbidden keys stay (no passwords, no raw tokens). Reasons are policy text, not row values.

## Database

Additive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, same style as v0.3.0 identity columns:

- `datagrant.requests.approvals jsonb` (default `[]`)
- no change required on `grants.approvers` (already `text[]`)

`sweep` already expires pending rows; it additionally writes `request_expired` when a signing key is present, and still expires the row if the receipt fails (access was never granted; exit 3 like revoke-without-receipt, documented).

## Exit codes

Existing 0-4 stay. New conditions map onto them; no exit 5.

| Situation | Exit |
| :---: | :---: |
| Policy deny, SoD fail, concurrent cap, quorum ineligible, expired pending | 1 |
| `--pending-ttl` above policy cap | 2 |
| Denied/not_approved/approval_recorded/request_expired receipt could not be written | 3 |
| Usage / identity flag conflicts | 2 (unchanged) |

## Threat model notes

- **DSN holders still bypass the CLI.** Limits, quorum, and SoD are workflow controls unless datagrant runs on a bastion that holds `DATAGRANT_DSN` (same OIDC story). Document that in security limits, do not pretend otherwise.
- **Local identity still lets anyone named `--as-user` vote.** Quorum of 2 in `identity.mode: local` is two claimed names, not two people. OIDC is what makes N-of-M real.
- **No break-glass in v0.4.0.** A reviewed policy edit to `auto` is the emergency path. That edit is itself an auditable git change; it is not a CLI shortcut.
- **Denial receipts grow the log.** `--apply` only. Reasons can still leak that a table or column name exists in policy; that is already true of today's stdout denials.
- **Concurrent cap races** under two writers. Document single-writer ops; do not add advisory locks in M2 unless tests show a cheap `SELECT ... FOR UPDATE` on a per-requester row is needed.
- **Quorum does not implement "approver A and approver B from different IdPs".** One policy, one identity mode, same as v0.3.0 mode parity.
- **SoD.** `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty. An approver who is only in a different `allowed_groups` entry than the requester is allowed. Sharing a broad group that is not in `allowed_groups` (for example `employees`) is allowed.

## Compatibility with v0.3.0

- Policies that omit every new key parse and evaluate as today (`approvals_required` effectively 1, no SoD extra, no concurrent cap, no `max_columns`, CLI `--pending-ttl` default 24h).
- Receipt JSONL from v0.3.0 remains valid input to `receipts verify`.
- `policy.version` stays `1`. A future breaking policy language would be a different milestone.
- Demo GIF and `make demo` stay local two-person with one approver unless a follow-up docs PR extends them.

## Test plan (each construction PR)

- Unit tests on `parse_policy` / `evaluate`: omitted keys; bad types; `approvals_required` on `auto`; dataset-level `approvals_required` is an error; `approvals_required` of 9 is an error; `max_columns` boundary (including `max_columns` > len(`columns`)); `pending_ttl` parse; unknown keys still fail.
- `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty. Case: `allowed_groups: [ml-team, analysts]`; requester alice in `ml-team`, approver bob in `analysts` only = allowed; bob also in `ml-team` = refused; both in `employees` only = allowed. `separation_of_duties: none` still allows the refused case.
- CLI tests: `--pending-ttl` above cap is exit 2; concurrent cap deny; `max_columns` deny; dry-run request does not write a `denied` receipt; `--apply` deny does write one and still exits 1; missing signing key on deny is exit 3 and no pending row.
- Quorum: first approve leaves pending; second distinct approve issues; same person twice fails; OIDC `(iss, sub)` duplicate fails; `approvers` list on the issued receipt has both names. N is policy-wide.
- Postgres integration: existing OIDC request/approve/revoke still passes with omitted new keys (compat).
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as OIDC: one concern per PR, tests and security checks in each, docs last. No break-glass PR.

1. **This PR.** Design, ROADMAP, audit pointer. No runtime.
2. **Policy limits in `policy.py` + CLI clamp.** Parse/validate `pending_ttl`, `max_columns`, `max_concurrent_grants`. `evaluate()` for column cap. CLI clamps `--pending-ttl` and counts active grants. Tests. No quorum, no new receipt events yet.
3. **Denial and expiry receipts.** Events `denied`, `not_approved`, `request_expired`. `--apply` only. Fail closed if the log cannot be written. `verify` on mixed v0.3.0 + new logs. Sweep writes `request_expired`.
4. **Quorum.** Policy-wide `approvals_required` (1..8), `approvals jsonb`, `approval_recorded`, issuing vote creates the grant. Tests including OIDC duplicate voter. Dataset-level key is a parse error.
5. **Separation of duties (`distinct-groups`).** Optional, default `none`. `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty. Tests as in the test-plan case, plus OIDC `group_map`.
6. **Docs, demo notes, CHANGELOG Unreleased, v0.4.0 prep (no tag).** `docs/policy.md`, `docs/cli.md`, `docs/security.md`, operations, this design marked implemented.

## Decisions (Chris, 2026-11-09 CT)

1. **No break-glass in v0.4.0.** Drop that construction PR. Emergency path is a reviewed policy edit to `approval: auto`.
2. **Quorum is policy-wide only.** No per-dataset `approvals_required` override.
3. `distinct-groups` refuses when (requester groups ∩ approver groups ∩ table `allowed_groups`) is non-empty.
4. **Denial and expiry receipts on `--apply` only.** Dry runs do not write.
5. **Warehouses are v0.5.0+.** v0.4.0 is this milestone only.
6. **Rate limits and `max_rows` stay out.**
7. **`approvals_required` is capped at 8.**
