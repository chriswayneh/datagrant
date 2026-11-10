# Design: approvals and policy limits (v0.4.0 / M2)

Status: proposed. Not implemented. This is the M2 design and execution plan from the v1.0 plan Chris authorized (approvals and policy limits, target v0.4.0). Construction must not start until this document is approved in [audit.md](../../aidlc-docs/audit.md). Roadmap: [ROADMAP.md](../../ROADMAP.md).

Grounded in the v0.3.0 code on `main` (`src/datagrant/policy.py`, `cli.py`, `pg/requests.py`, `pg/grant.py`, `receipt.py`).

## Goal

v0.3.0 can prove *who* asked and who approved (OIDC), but the approval *workflow* is still one other person in a global `approvers` group, and most limits are duration plus column allow-lists. Operators who need four-eyes on a sensitive dataset, a cap on how many live grants one person holds, or evidence of denials have to invent that outside datagrant.

M2 tightens **approvals** and **policy-enforced limits** without turning datagrant into a ticket system or an identity provider. Default omitted keys keep v0.3.0 behavior so existing policies and receipt logs keep working.

Out of scope for M2: other warehouses (proposed v0.5.0+), a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, and anything that only the holder of `DATAGRANT_DSN` could bypass anyway without a real enforcement point.

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
| N-of-M quorum (policy-wide, optional per-dataset override) | **Keep** | Real gap: today N is always 1. Sensitive datasets often want 2. Per-dataset override avoids a second policy file. |
| Sensitivity labels as a new taxonomy | **Cut** | Per-dataset `approvals_required` and existing `max_duration` already express "this table is hotter". A label vocabulary would be unused config. |
| Separation of duties: optional no-shared-group | **Keep** (optional, default off) | Distinct-person is not enough when requester and approver are both in `ml-team` and `ml-team` is also an approver group. Default off so current policies do not break. |
| `max_duration` as a new feature | **Already shipped** | Document only. |
| `max_columns` per table | **Keep** | Cheap. Stops "request every allowed column" when the allow-list is wide. Omit = unlimited (today). |
| `max_rows` at grant time | **Cut** | A `COUNT(*)` on the future view is racy, slow, and still not what the grantee will query. Row limits stay the job of `row_filters`. |
| `max_concurrent_grants` per principal | **Keep** | Count `datagrant.grants` rows with `status = 'active'` for that requester. Re-check at approve time. Same-transaction for `auto`. |
| Request rate limits (N per hour) | **Cut** | No daemon. Anyone with the admin DSN skips the CLI. A clock table would look like security and not be. |
| Policy-capped pending TTL | **Keep** | Promotes `--pending-ttl` to a policy max. CLI may only shorten. |
| Break-glass | **Keep, default off, needs a yes from Chris** | Narrow: listed groups, mandatory `--reason` (bounded text), still OIDC/local identity, still a receipt with `details.break_glass`. Does not skip identity. Does not mint a second admin DSN. |
| Denial reasons in receipts | **Keep** ( `--apply` only) | Compliance asked for evidence of "who was refused". Dry runs stay silent in the log. |
| `policy check` for the new keys | **Keep** | Same PR as schema. |
| v0.3.0 policy and receipt compatibility | **Keep** (hard requirement) | Omit new keys; old JSONL verifies. |

## Policy configuration

`policy.version` stays `1`. Unknown keys remain errors. New keys are optional.

```yaml
version: 1
approval: two-person
approvers: [sec]
approvals_required: 1          # optional; default 1; only legal when approval is two-person
separation_of_duties: none     # optional; none (default) or distinct-groups
pending_ttl: 24h               # optional; cap for --pending-ttl; default 24h if omitted
max_concurrent_grants: 3       # optional; omit = no cap
max_duration: 8h               # already required
# break_glass_groups: [sec]    # optional; omit = no break-glass
groups:
  ml-team: [alice]
  sec: [carol]
datasets:
  - name: clinic
    database: clinicdb
    approvals_required: 2      # optional override; only when policy approval is two-person
    max_concurrent_grants: 1   # optional; tighter of policy-wide and dataset
    tables:
      - name: public.patients
        allowed_groups: [ml-team]
        max_columns: 4         # optional; omit = no extra cap beyond the allow-list
        max_duration: 4h
        columns: { patient_id: hash, zip: partial }
```

Validation (`datagrant policy check` enforces all of this offline):

- `approvals_required` is a positive integer, at most 8 (keeps the pending row small). Illegal when `approval: auto`. If omitted under `two-person`, it is `1` (today).
- Dataset `approvals_required` is the same type, and is a policy error under `auto`. It may be higher or lower than the policy-wide value; the dataset value wins for requests on that dataset.
- `separation_of_duties`: `none` or `distinct-groups`. Unknown strings are errors. `distinct-groups` means the approver's policy groups (static plus `group_map`) must not intersect the requester's. It does not replace distinct-person / `(iss, sub)`.
- `pending_ttl` uses the existing duration grammar (`m`/`h`/`d`, no seconds), `1m`..`7d`. CLI `--pending-ttl` that exceeds it is a usage error (exit 2) before the database write.
- `max_concurrent_grants` is a positive integer, policy-wide and/or per dataset. Effective cap is the minimum of those that are set.
- `max_columns` is a positive integer per table. A request whose unique column count exceeds it is denied. It cannot exceed the size of `columns`.
- `break_glass_groups` is a list of existing `policy.groups` names. Empty/omitted means the CLI flag is refused (exit 2). Members still need a valid caller identity.

## Evaluation and CLI

`evaluate()` grows new deny reasons; it stays deny-by-default and still returns every reason. Concurrent-grant counting needs a database read, so it lives in `cmd_request` / `cmd_approve` next to the existing catalog lookup, not inside pure `evaluate()`. The count is `status = 'active'` only (revoked and expired do not count). Two `auto` `--apply` races are accepted as a residual (CLI is one writer in the documented ops model); the insert stays in the existing grant transaction.

**Quorum (`approvals_required` > 1).** `datagrant.requests` gains an additive `approvals jsonb` (list of `{approver, at, identity}` objects) and keeps `status` in `pending|approved|expired`. Each `approve --apply`:

1. Re-runs today's identity, SoD, and policy checks.
2. Refuses a second vote from the same person (name and, in OIDC, `(iss, sub)`).
3. Appends the vote.
4. If `len(votes) < N`, leaves the row `pending`, prints how many remain, writes no grant, writes a receipt event `approval_recorded`.
5. If `len(votes) == N`, creates the grant in the same transaction as today, sets `status = approved`, copies all voters into `grants.approvers` and `approver_identities`.

Dry-run `approve` reports whether this caller would be vote 1 of N or the issuing vote.

**Break-glass (only if Chris says yes).** `request --break-glass --reason TEXT --apply` in `two-person` policy:

- `--reason` required, 8..512 printable characters, stored in the receipt `details.reason` (and grant `details`), never in argv-adjacent logs beyond the receipt.
- Caller must be in `break_glass_groups`.
- Still evaluates the request (dataset, columns, duration, concurrent cap). It does **not** skip OIDC, duration caps, or `max_concurrent_grants`.
- It *does* skip waiting for quorum: the grant is issued immediately with `approval: two-person` plus `details.break_glass: true`.
- `auto` policies refuse `--break-glass` (exit 2): there is nothing to break.

There is no separate review command. Review is `receipts verify` plus grepping `details.break_glass` (and `--json`).

**Denial receipts** only on `--apply` that actually refused (policy deny, SoD, quorum-ineligible, expired pending, concurrent cap). Dry runs do not write. Signing key required; if the receipt cannot be written, exit 3 and **do not** create a pending row or grant (fail closed, same as issued).

## Receipt schema

`RECEIPT_VERSION` stays `1`. `verify()` already accepts any signed body with a valid chain, so old v0.3.0 lines keep verifying.

New events (writer allow-list only):

| Event | When | `grant_id` | Notes |
| --- | --- | --- | --- |
| `denied` | `request --apply` refused by policy or limits | omitted | `details.reasons` (list of strings), `details.phase: request` |
| `not_approved` | `approve --apply` refused | omitted; `details.request_id` set | `details.reasons`, `details.phase: approve` |
| `approval_recorded` | quorum vote that did not yet issue | omitted; `details.request_id` | `details.approvals_recorded`, `details.approvals_required` |
| `request_expired` | `sweep` expires a pending request | omitted; `details.request_id` | Evidence that a password was issued to the requester and never approved |

`issued` gains optional `details.break_glass` and `details.reason` when used. `approvers` and `approver_identities` already lists; quorum fills them with every voter.

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
| `--pending-ttl` above policy cap, `--break-glass` without `--reason` or on `auto`, `--break-glass` when `break_glass_groups` omitted | 2 |
| Denied/not_approved/approval_recorded/request_expired receipt could not be written | 3 |
| Usage / identity flag conflicts | 2 (unchanged) |

## Threat model notes

- **DSN holders still bypass the CLI.** Limits, quorum, SoD, and break-glass are workflow controls unless datagrant runs on a bastion that holds `DATAGRANT_DSN` (same OIDC story). Document that in security limits, do not pretend otherwise.
- **Local identity still lets anyone named `--as-user` vote.** Quorum of 2 in `identity.mode: local` is two claimed names, not two people. OIDC is what makes N-of-M real.
- **Break-glass is a loaded gun.** Mandatory reason and a distinctive receipt are the review hook. If Chris does not want it in v0.4.0, drop PR 6; the rest of M2 does not depend on it.
- **Denial receipts grow the log.** `--apply` only. Reasons can still leak that a table or column name exists in policy; that is already true of today's stdout denials.
- **Concurrent cap races** under two writers. Document single-writer ops; do not add advisory locks in M2 unless tests show a cheap `SELECT ... FOR UPDATE` on a per-requester row is needed.
- **Quorum does not implement "approver A and approver B from different IdPs".** One policy, one identity mode, same as v0.3.0 mode parity.

## Compatibility with v0.3.0

- Policies that omit every new key parse and evaluate as today (`approvals_required` effectively 1, no SoD extra, no concurrent cap, no `max_columns`, CLI `--pending-ttl` default 24h).
- Receipt JSONL from v0.3.0 remains valid input to `receipts verify`.
- `policy.version` stays `1`. A future breaking policy language would be a different milestone.
- Demo GIF and `make demo` stay local two-person with one approver unless a follow-up docs PR extends them.

## Test plan (each construction PR)

- Unit tests on `parse_policy` / `evaluate`: omitted keys; bad types; `approvals_required` on `auto`; `max_columns` boundary; `pending_ttl` parse; SoD none vs distinct-groups on overlapping groups; unknown keys still fail.
- CLI tests: `--pending-ttl` above cap is exit 2; concurrent cap deny; `max_columns` deny; dry-run request does not write a `denied` receipt; `--apply` deny does write one and still exits 1; missing signing key on deny is exit 3 and no pending row.
- Quorum: first approve leaves pending; second distinct approve issues; same person twice fails; OIDC `(iss, sub)` duplicate fails; `approvers` list on the issued receipt has both names.
- Postgres integration: existing OIDC request/approve/revoke still passes with omitted new keys (compat).
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as OIDC: one concern per PR, tests and security checks in each, docs last.

1. **This PR.** Design, ROADMAP, audit pointer. No runtime.
2. **Policy limits in `policy.py` + CLI clamp.** Parse/validate `pending_ttl`, `max_columns`, `max_concurrent_grants`. `evaluate()` for column cap. CLI clamps `--pending-ttl` and counts active grants. Tests. No quorum, no new receipt events yet.
3. **Denial and expiry receipts.** Events `denied`, `not_approved`, `request_expired`. `--apply` only. Fail closed if the log cannot be written. `verify` on mixed v0.3.0 + new logs. Sweep writes `request_expired`.
4. **Quorum.** `approvals_required`, `approvals jsonb`, `approval_recorded`, issuing vote creates the grant. Policy-wide and per-dataset. Tests including OIDC duplicate voter.
5. **Separation of duties (`distinct-groups`).** Optional, default `none`. Tests with overlapping vs disjoint groups, OIDC `group_map`.
6. **Break-glass (only if Chris says yes).** Flag, reason bounds, group check, `details.break_glass` on `issued`. Tests for `auto` refuse, missing reason, identity still required.
7. **Docs, demo notes, CHANGELOG Unreleased, v0.4.0 prep (no tag).** `docs/policy.md`, `docs/cli.md`, `docs/security.md`, operations, this design marked implemented.

## Open questions for Chris

1. Is **break-glass** in v0.4.0, or drop PR 6 and leave emergency access as "edit the policy to `auto` under review"?
2. Should **quorum** be policy-wide only, or is the per-dataset override worth the extra key?
3. For **distinct-groups** SoD: is "no shared policy group at all" the rule you want, or should we only forbid sharing the table's `allowed_groups` (so both can still sit in `employees`)?
4. Should **denial receipts** fire on `--apply` only (this design) or also on dry-run (noisier log)?
5. Confirm **warehouses** move to v0.5.0+ so v0.4.0 is this milestone only.
6. Confirm **rate limits** and **max_rows** stay out.
7. Any cap other than 8 on `approvals_required`?
