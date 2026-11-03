# Operations

The full runbook lives in the AI-DLC operations artifacts: [aidlc-docs/operations/runbook.md](../aidlc-docs/operations/runbook.md). It covers:

- **Database hardening before the first grant.** Revoke risky `PUBLIC` defaults (run `datagrant preflight` to list them) and install `pgcrypto` if you use `hash` masks.
- **The admin role.** It must be able to end grantee sessions (`pg_signal_backend` unless it's a superuser). Otherwise revoke and sweep fail closed. Disable statement logging for it.
- **Scheduling `sweep`.** A cron line or systemd timer every minute. Expired grants stay usable for open sessions until the sweep runs.
- **Keys and receipts.** Back up the hash key, the signing key and the receipt log; publish the public key; record the head hash from `receipts verify` off the host.
- **CLI operation.** Exit codes for alerting (`3` and `4` need a human), and `grant status` to read `last_error`.

To try everything safely first, see [demo.md](demo.md).
