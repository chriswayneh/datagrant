# Operations

The full runbook lives in the AI-DLC operations artifacts: [aidlc-docs/operations/runbook.md](../aidlc-docs/operations/runbook.md). It covers:

- **Database hardening before the first grant.** Revoke risky `PUBLIC` defaults (run `datagrant preflight` to list them) and install `pgcrypto` if you use `hash` masks.
- **The admin role.** It must be able to end grantee sessions (`pg_signal_backend` unless it's a superuser). Otherwise revoke and sweep fail closed. To keep passwords and hash-key parameters out of the server log it also needs to `SET log_statement` (superuser, or PostgreSQL 15+ `GRANT SET ON PARAMETER log_statement TO <admin>`). Without that privilege, `request`/`approve --apply` refuse; revoke and sweep still run. Residual: superuser `log_min_duration_statement = 0` can still leak parameters. `log_min_error_statement` (default `error`) still logs the full text of a failing statement, so a failed `CREATE ROLE` can log its verifier literal; lowering it needs the same SUSET privilege.
- **Scheduling `sweep`.** A cron line or systemd timer every minute. Expired grants stay usable for open sessions until the sweep runs.
- **Keys and receipts.** Back up the hash key, the signing key and the receipt log; publish the public key; record the head hash from `receipts verify` off the host.
- **CLI operation.** Exit codes for alerting (`3` and `4` need a human), and `grant status` to read `last_error`.

## External receipt sink (v0.2.0)

Details: [CLI reference](cli.md#receipt-sink) and [design](design/receipt-sink.md).

**Webhook.** Run a receiver you control at an HTTPS URL. It must accept `POST <url>` (NDJSON, one signed receipt line) with a 2xx, answer `GET <url>/head` with `{"seq": N, "head_sha256": "<sha256 of the last line>"}` (404 when empty), and refuse a different line at a `seq` it already stored. Ideally it checks each signature with the key from `datagrant keys export-pubkey` and writes to storage with retention (for example an object-locked bucket or a SIEM).

```sh
export DATAGRANT_RECEIPT_SINK=https://receipts.example.internal/datagrant
export DATAGRANT_RECEIPT_SINK_TOKEN=...      # from your secret store, never on the command line
export DATAGRANT_RECEIPT_SINK_MODE=required  # or best-effort (default)
```

**File sink.** Point it at an append-only location the datagrant host can't rewrite, such as a remote mount with `chattr +a`: `DATAGRANT_RECEIPT_SINK=file:///mnt/receipts/datagrant.jsonl`.

**Cron.** Flush the outbox and check the sink on a schedule, next to `sweep`:

```cron
* * * * *   datagrant sweep --apply
*/5 * * * * datagrant receipts push --apply || alert "receipts pending"
0 * * * *   datagrant receipts verify --sink "$DATAGRANT_RECEIPT_SINK" || alert "receipt chain or sink mismatch"
```

`receipts push --apply` exits 3 while anything is still pending. `receipts verify --sink` exits 1 on a mismatch or an unreachable sink; treat that as an incident, not noise.

**Recovering a lost or replaced sink.** `verify --sink` reports "sink is behind its own acknowledgements". First confirm the local log is intact (`receipts verify` with `--expect-head` if you have a recorded head). Then restore the sink from its own backup if you can. If you must re-seed a new, empty sink from the local log, move the cursor aside (`mv <receipt-log>.sink <receipt-log>.sink.old`) and run `receipts push --apply`; every receipt is resent from `seq` 0. Record why in your incident notes, because the off-host copy now comes from the host it was meant to check.

**Recovering a corrupt or unusable cursor.** New grants stop with exit 3 ("receipt outbox unusable") and `verify --sink` fails closed. Fix permissions if that's the cause (`chmod 600 <receipt-log>.sink`, and make sure it isn't a symlink). If the content is corrupt, compare `receipts verify --sink` output after moving the cursor aside: with no cursor, verify still checks the sink head against the log. Then either restore the cursor from backup or remove it and run `receipts push --apply` (already delivered lines are resent and ignored by an idempotent sink). Never edit `acked_seq` upward by hand.

To try everything safely first, see [demo.md](demo.md).

## Ops hardening (v0.5.0)

Details: [CLI](cli.md), [policy](policy.md), [security limits](security.md#known-limits), [design](design/ops-hardening.md).

These are host and database workflow controls. Anyone who holds `DATAGRANT_DSN` can still connect to Postgres directly. Run datagrant on a bastion that holds the DSN when you need them as an enforced control.

**`datagrant doctor`.** Read-only. Checks keys, policy parse, POSIX file modes, DSN connect, PUBLIC preflight warnings, `pg_signal_backend` (or superuser), ability to `SET log_statement` (superuser, or PostgreSQL 15+ `has_parameter_privilege`; does not issue SET), receipt-log chain, optional sink cursor. Exit 0 if every check passes, 1 if any fail, 2 on usage. Warnings do not fail. No `--apply`. Does not create schemas, keys, or grants, and does not take the advisory lock.

**Advisory lock.** Mutating `--apply` takes a session `pg_advisory_lock` on `DATAGRANT_ADVISORY_LOCK_KEY` (`0x64677401`) before the live-grant count. `request` / `approve` / `preflight --apply` wait up to 30s, then fail closed (exit 3, no grant) if another session still holds the key. `revoke` / `sweep` use `pg_try_advisory_lock` and proceed without the lock if it is busy (they warn with the holding pid(s)). Dry runs do not lock. `PUBLIC` can `EXECUTE pg_advisory_lock`; treat the lock as a coordination aid among writers, not as enforcement against grantees.

**`strict_preflight`.** Optional, omit or `false` to keep PUBLIC warnings and still grant. `true` means `--apply` on `request`, `approve`, and `preflight` exits 1 when those PUBLIC defaults remain. `preflight --apply` still creates datagrant state before refusing. `revoke` and `sweep` never refuse for this reason.

**File modes (POSIX).** A group/other-accessible receipt log is refused on access-creating `--apply` (exit 1). `revoke` / `sweep` warn, still revoke, and exit 3. Policy-file mode warns by default (`group/other-accessible`; writable is the stronger finding). Optional `strict_policy_permissions: true` refuses access-creating `--apply` only. That in-file key is defeated by write access to the policy file. `--strict-policy-permissions` or `$DATAGRANT_STRICT_POLICY_PERMISSIONS` (`1`/`true`/`yes`/`on`) forces the same check from outside the file and inspects the mode before the YAML is parsed. Unset, empty, or `0`/`false`/`no`/`off` leaves the override off. Any other non-empty value is exit 2 on access-creating `--apply` and `doctor`; `revoke` and `sweep` do not parse the variable.

**`SET LOCAL log_statement`.** `apply_plan` and two-person `create_request` issue `SET LOCAL log_statement = 'none'` in the grant/request transaction when the admin can SET that GUC. `request` / `approve --apply` refuse (exit 1) if it cannot. `revoke` / `sweep` proceed without SET. Doctor reports the privilege and never SETs. Residual: `log_min_duration_statement = 0` and `log_min_error_statement` can still capture parameters or a failed `CREATE ROLE` verifier.

`make demo` omits `strict_preflight` and `strict_policy_permissions` (CI Postgres has PUBLIC defaults; demo policy files stay 0644). It does not walk `datagrant doctor`.

## Approvals and policy limits (v0.4.0)

Details: [policy](policy.md), [CLI](cli.md), [security limits](security.md#known-limits), [design](design/approvals-policy-limits.md).

These are CLI workflow controls. Anyone who holds `DATAGRANT_DSN` can still connect to Postgres directly. In `identity.mode: local`, `approvals_required` is N claimed names and `distinct-groups` is only as strong as the claimed names. For real N-of-M, run datagrant on a bastion that holds the DSN and requires OIDC tokens.

**Policy keys (all optional; omit them for v0.3.0 behavior).** `policy.version` stays `1`. Check with `datagrant policy check`.

- `pending_ttl` (`1m`..`7d`): cap on an explicit `request --pending-ttl` in two-person mode (exit 2 if the flag is longer). If the flag is omitted, the lifetime is `min(24h, policy.pending_ttl)`.
- `max_columns` per table: deny a request whose unique column count exceeds it. It cannot exceed the size of `columns`.
- `max_concurrent_grants` policy-wide and/or per dataset: effective cap is the minimum of those set. Count is `status = 'active' AND expires_at > now()` for that requester on `request` and `approve`. Revoked grants and grants past `expires_at` (swept or not) do not count. Overlapping `--apply` is serialized by the v0.5.0 session advisory lock (see [Ops hardening](#ops-hardening-v050)).
- `approvals_required` (1..8, default 1): policy-wide only, `two-person` only. Dataset-level key is a load error. Votes are stamped with `policy.sha256`; a policy edit means previous votes no longer count. The Nth vote commits with the grant; if the locked counted names do not match the plan, apply fails closed and the request stays pending (retry).
- `separation_of_duties: none` (default) or `distinct-groups`. `distinct-groups` refuses approve when requester groups ∩ approver groups ∩ the table's `allowed_groups` is non-empty.

**Receipts, `--apply` only.** Dry runs write nothing. `denied` (refused request), `not_approved` (refused approve), `approval_recorded` (partial quorum vote), `request_expired` (sweep expired a pending request). A `denied` / `not_approved` / `approval_recorded` receipt that cannot be written is exit 3 and creates no pending row or grant. Sweep still expires the pending row if `request_expired` cannot be written (exit 3). Alert on exit 3 the same way as today.

There is no break-glass command. Emergency access is a reviewed policy edit to `approval: auto`.

`make demo` stays local two-person with one approver. It does not walk quorum N>1, SoD, or the new limit keys.

## OIDC identity (v0.3.0)

Details: [policy](policy.md#identity), [CLI](cli.md#oidc-identity), [security limits](security.md#known-limits), [demo](demo-oidc.md).

datagrant does not log people in. Put `identity.mode: oidc` in the policy, point `issuer` and `audience` at your IdP, and have each caller present a short-lived ID token:

```sh
# token file: 0600 regular file, never a command-line value
umask 077
# obtain an ID token from your IdP into $HOME/.config/datagrant/id.jwt
datagrant request --oidc-token-file "$HOME/.config/datagrant/id.jwt" ... --apply
datagrant approve REQUEST_ID --oidc-token-file "$HOME/.config/datagrant/id.jwt" --apply
```

`$DATAGRANT_OIDC_TOKEN` is the env fallback (file beats env). Treat it like the DSN: anything that can read the process environment can read the token.

**Where this is a real control.** Run the CLI where callers cannot use `DATAGRANT_DSN` or write `policy.yaml`. On a laptop that already has the admin DSN, OIDC only proves which token was presented to this process.

**JWKS cache.** Default `~/.cache/datagrant/jwks` (`0700` / `0600`). Override with `DATAGRANT_JWKS_CACHE_DIR`. After an IdP signing-key compromise, delete that directory (or set `jwks_cache_ttl: 0s` in policy). Do not set `DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST` outside tests.

**Approvals across policy edits.** A pending `oidc` request cannot be approved under a `local` policy, and the reverse is also refused. Changing `issuer` or `username_claim` between request and approve also refuses. Requester groups at approve time are remapped from the stored IdP groups through the current `group_map` when `groups_claim` still matches.

**`revoke` and `sweep`** still do not take a token. Schedule them as today.
