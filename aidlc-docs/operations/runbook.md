# runbook

**Status:** Drafted during Construction (U2–U7). Review is the next step, in the Operations stage.

## Steps

### Database hardening before first grant (U2)
Grant roles inherit `PUBLIC` privileges. As a DBA, before enabling datagrant:

```sql
-- every database grant roles must NOT reach:
REVOKE CONNECT, TEMP ON DATABASE other_db FROM PUBLIC;
GRANT CONNECT ON DATABASE other_db TO app_users;   -- re-grant to real users/groups
-- the dataset database:
REVOKE TEMP ON DATABASE clinicdb FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;        -- default already on Postgres 15+
```

Re-run setup and confirm `preflight` reports no warnings.

### Admin permissions for revoke/sweep (U4)
The datagrant admin role must be able to end grant sessions:

```sql
GRANT pg_signal_backend TO datagrant_admin;   -- not needed if the admin is superuser
```

Without it, revoke/sweep fail closed: the grant stays `active`, `last_error` is set on
`datagrant.grants`, the role is set `NOLOGIN`, and the next sweep retries.

### Schedule the sweep (U4)
`VALID UNTIL` only blocks new logins; sweep ends live sessions and drops roles/views.
Run it every minute or few minutes.

cron (`crontab -e` for the datagrant service user):

```cron
* * * * * DATAGRANT_DSN=postgresql:///clinicdb datagrant sweep --apply >> /var/log/datagrant-sweep.log 2>&1
```

systemd timer:

```ini
# /etc/systemd/system/datagrant-sweep.service
[Service]
Type=oneshot
User=datagrant
Environment=DATAGRANT_DSN=postgresql:///clinicdb
ExecStart=/usr/local/bin/datagrant sweep --apply

# /etc/systemd/system/datagrant-sweep.timer
[Timer]
OnCalendar=*:0/1
Persistent=true
[Install]
WantedBy=timers.target
```

`systemctl enable --now datagrant-sweep.timer`. Alert on non-zero exit, and check
`SELECT id, last_error FROM datagrant.grants WHERE last_error IS NOT NULL`.

### Keys and receipts (U5)
Create keys once (refuses to overwrite): `datagrant keys init --apply`. Files are 0600 in a 0700 directory, by default `~/.config/datagrant/{hash,signing}.key`, or set `DATAGRANT_HASH_KEY` / `DATAGRANT_SIGNING_KEY` to file paths.

- **Back up** both key files to an encrypted secret store (e.g. a password manager or KMS-encrypted object). Losing `hash.key` changes every hash mask; losing `signing.key` means new receipts can't be signed with the same key id.
- **Export the public key** (`datagrant keys export-pubkey`, 64 hex) and give it to auditors with the receipt log. They verify with `datagrant receipts verify --pubkey <hex> --receipt-log <file>`. Record the printed head hash somewhere outside the host (ticket or SIEM) so later truncation is detectable with `--expect-head`.
- **Rotate the signing key:** stop grants and sweep, archive the current log (`receipts-<date>.jsonl`) together with its public key and head hash, move the old key aside, create a new key, then start a new log. Each log verifies with exactly one key.
- **Rotate the hash key:** only between grants; existing hashed values change. Old rows in `datagrant.hash_keys` can be deleted once no active grant references them.
- The receipt log (`DATAGRANT_RECEIPT_LOG`, default `~/.config/datagrant/receipts.jsonl`) must stay 0600. Ship it off-host regularly. Never edit it by hand: a partial last line blocks new grants until fixed.

### CLI operation (U6)
```bash
export DATAGRANT_DSN='postgresql://datagrant_admin@db/clinicdb'   # password via ~/.pgpass, not the DSN
export DATAGRANT_POLICY=/etc/datagrant/policy.yaml
datagrant keys init --apply && datagrant keys export-pubkey   # give the public key to auditors
datagrant preflight --apply                           # creates state, warns on PUBLIC defaults
datagrant request --dataset clinic --table public.patients --columns patient_id,zip \
  --row-filter "region = 'west'" --duration 2h --purpose "model eval" --apply
datagrant approve <request-id> --apply                # two-person mode, a different person
datagrant grant list ; datagrant revoke <grant-id> --apply ; datagrant sweep --apply
datagrant receipts verify --expect-head <recorded head>
```
Every changing command (keys init, request, approve, revoke, sweep, preflight) is a **dry run unless `--apply`** is given: it prints the plan and changes nothing, and a dry run never creates or prints a password. `--dry-run` is accepted as a no-op alias, and `--apply --dry-run` together is a usage error. `datagrant doctor` is read-only and does not take `--apply`.
Exit codes: 0 ok, 1 denied/failed, 2 usage, 3 receipt not written or access-creating `--apply` timed out on the advisory lock, 4 revoke failed. Alert on 3 and 4 from the sweep timer.
Key paths resolve as `--signing-key`/`--hash-key` > env vars > `keys init --dir` > `~/.config/datagrant/`. Pass the same flags (or env) to every command. A flag that doesn't apply to a command is rejected (exit 2).
Identity defaults to the OS user; `--as-user` is not authentication. Optional `policy.identity.mode: oidc` (v0.3.0) verifies ID tokens on `request` and `approve`. Holding the admin DSN still bypasses the CLI, so for real two-person control run datagrant behind a service that authenticates users and holds the admin DSN. v0.4.0 adds optional `pending_ttl`, `max_columns`, `max_concurrent_grants`, policy-wide `approvals_required` (1..8), and `separation_of_duties: distinct-groups`. Those are CLI workflow controls; in local mode quorum and SoD are claimed names. `--apply` refusals write `denied` / `not_approved`; a partial quorum vote writes `approval_recorded`; sweep writes `request_expired` for expired pending requests. Dry runs write nothing. Exit 3 on a failed denial or `approval_recorded` receipt means nothing was issued. v0.5.0 adds a session advisory lock on mutating `--apply` (`request` / `approve` / `preflight --apply` fail closed exit 3 after 30s; `revoke` / `sweep` proceed without the lock on contention), `datagrant doctor`, optional `strict_preflight` and `strict_policy_permissions`, `--strict-policy-permissions` / `$DATAGRANT_STRICT_POLICY_PERMISSIONS`, receipt-log 0600 on access-creating `--apply`, and `SET LOCAL log_statement = 'none'` when the admin can SET it (`request` / `approve --apply` refuse if it cannot). There is no break-glass command; emergency access is a reviewed policy edit to `approval: auto`. See [docs/operations.md](../../docs/operations.md).

## Approval
Record approval in ../audit.md.
