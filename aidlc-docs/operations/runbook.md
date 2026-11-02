# runbook (template)

**Status:** Not started (v0.9.0).

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
* * * * * DATAGRANT_DSN=postgresql:///clinicdb datagrant sweep >> /var/log/datagrant-sweep.log 2>&1
```

systemd timer:

```ini
# /etc/systemd/system/datagrant-sweep.service
[Service]
Type=oneshot
User=datagrant
Environment=DATAGRANT_DSN=postgresql:///clinicdb
ExecStart=/usr/local/bin/datagrant sweep

# /etc/systemd/system/datagrant-sweep.timer
[Timer]
OnCalendar=*:0/1
Persistent=true
[Install]
WantedBy=timers.target
```

`systemctl enable --now datagrant-sweep.timer`. Alert on non-zero exit, and check
`SELECT id, last_error FROM datagrant.grants WHERE last_error IS NOT NULL`.
(The `datagrant sweep` command and its DSN setting are wired in U6.)

## Approval
Record approval in ../audit.md.
