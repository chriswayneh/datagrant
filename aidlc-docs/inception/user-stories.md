# User stories (draft)

| ID | As a… | I want… | So that… | Acceptance |
| --- | --- | --- | --- | --- |
| US-1 | AI developer | to request specific columns/rows for N hours from the CLI | I can work without standing access | Allowed request returns credentials + grant id in <10 s |
| US-2 | AI developer | sensitive columns masked automatically | I see only what I need | Masked columns never return raw values via the grant role |
| US-3 | Data owner | to define access in a reviewable policy file | rules live in git, not in people's heads | Requests outside policy are denied with a reason |
| US-4 | Data owner | a hard cap on grant duration | access can't linger | Duration > policy max is rejected |
| US-5 | DBA | expired grants revoked automatically | I don't clean up by hand | `sweep` drops role/view and kills sessions; rerun is a no-op |
| US-6 | Developer / DBA | to revoke early | access ends when the work does | `revoke <id>` ends access immediately and emits a receipt |
| US-7 | Compliance reviewer | signed receipts I can verify offline | I have tamper-evident evidence | `receipt verify` passes on intact, fails on altered receipts |
| US-8 | DBA | a dry run | I can review the SQL first | `--dry-run` prints SQL, changes nothing |
