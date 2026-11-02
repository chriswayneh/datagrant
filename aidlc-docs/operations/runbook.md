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

## Approval
Record approval in ../audit.md.
