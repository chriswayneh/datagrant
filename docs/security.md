# Security model

datagrant narrows, time-boxes and records access to regulated tables in Postgres. This page explains what it defends against, what it trusts, and where it stops. Report vulnerabilities privately: see [SECURITY.md](../SECURITY.md).

## Assets

- Rows and columns of regulated tables (PHI/PII).
- The admin DSN, which can create and drop roles.
- The hash key (it determines hash outputs) and the signing key (it vouches for receipts).
- The receipt log, which is the evidence of who saw what.

## Trust boundaries

| Party | Trusted to |
| --- | --- |
| Operator holding the admin DSN and keys | Run datagrant honestly. They can bypass it entirely. |
| Requester / grantee | Nothing beyond the granted view, until it expires. |
| Approver | Approve in good faith. Identity is not verified (see below). |
| Policy file | Is the source of truth. Protect it like code: review it and limit who can write it. |
| Postgres | Enforces roles, privileges, `security_barrier` views and session termination. |

## What it defends

- **Over-broad access.** Only policy-listed columns and exact-match row filters. Deny by default, with reasons.
- **Standing access.** Every grant has an expiry. `sweep` revokes it, and `VALID UNTIL` is a database-side backstop for new logins.
- **Raw-table reads.** The grantee role gets `SELECT` on one masked `security_barrier` view only, not on the base table.
- **SQL injection via policy or request.** Identifiers and literals are composed with `psycopg.sql`, row filters are parsed against a small grammar, and grant DDL runs with a pinned `search_path` and `pg_catalog`-qualified functions.
- **Lingering sessions.** Revoke first commits a lockout (`NOLOGIN`, expired `VALID UNTIL`, no password), then terminates sessions, then drops the role. A failed revoke leaves the role locked out and records `last_error`.
- **Password exposure.** Only SCRAM verifiers are sent to the server. The plaintext is shown once, to the requester.
- **Tail truncation or replacement of the local log, with a sink (v0.2.0).** Each receipt is also sent to an external sink (HTTPS webhook or an append-only file elsewhere). `receipts verify --sink` fails if the sink is ahead of the local log, if the hashes differ at the same `seq`, or if the sink falls behind what it already acknowledged. `required` mode refuses access whose `issued` receipt can't reach the sink.
- **Silent or forged audit edits.** Receipts are canonical JSON signed with ed25519 and hash-chained. `verify` reports the first altered, reordered, deleted or inserted entry. No receipt, no access: if the `issued` receipt can't be written, the grant is revoked.
- **Key file tricks.** Key files are opened without following symlinks and must be private regular files. `keys init` won't overwrite a key or put both keys in one file.

## Known limits

- **Identity is not authentication.** The requester and approver names come from the OS user or `--as-user`. Anyone with the admin DSN can claim any name, so two-person approval is a workflow control, not an enforced one. To enforce it, run datagrant behind a service that authenticates people and keeps the DSN to itself. OIDC identity is on the [roadmap](../ROADMAP.md).
- **Short DSN passwords in diagnostics.** Error redaction always strips `user:pass@` and `password=` forms. The password string itself is only globally replaced when it is at least 4 characters, so a 1-3 character password can still appear as a bare substring in a message. Use a longer admin password.
- **Filters still reveal something.** A column in `filter_columns` is not in the view, but the grantee knows every row they see matches the filter (for example `region = 'west'`). A row filter on a column from `columns` leaves that column visible as usual.
- **Masks leak shape.** NULLs stay NULL under `partial` and `hash`, and `partial` keeps value length. Pick `redact` or `null` when shape matters.
- **Hashes are linkable within a scope.** Each dataset hashes under its own derived key (`hash_scope`, default the dataset name), so equal values don't match across datasets. Within one scope (every grant on that dataset, or datasets that share a `hash_scope`) equal values still hash equally, and anyone holding the hash key file can recompute any scope's hashes.
- **Tail truncation.** Deleting the newest receipts leaves a valid shorter chain. Configure an external receipt sink and run `receipts verify --sink`, or record the head hash off the host and use `receipts verify --expect-head`.
- **The sink only covers what it has.** Receipts after the sink head (the outbox) can't be checked off-host until they're delivered. In `best-effort` mode someone with host access can delete them before `receipts push` runs; `required` mode closes this for `issued` receipts only, and revoke receipts are always best effort.
- **The sink is only as strong as its receiver.** A webhook that accepts rewrites, a bucket without retention, or a file sink on storage the datagrant host can rewrite adds little. Keep the sink under separate administration. Anyone with the signing key and the sink token can send forged receipts for future `seq` values: the sink proves what was sent, not that it was true.
- **The sink token lives in the environment.** `DATAGRANT_RECEIPT_SINK_TOKEN` is readable by the datagrant process, by anything that can read its environment (same user, root, `/proc` on Linux) and by whatever launches it. It is never printed, but treat it like the DSN.
- **No sink lock on Windows.** Like the receipt log, the file sink and the outbox flush aren't locked on Windows; run one writer at a time there.
- **Symlinked parent directories.** Key files, the receipt log, the cursor and the file sink refuse a symlink as the final path component, but parent directories are followed. Keep those directories owned by the datagrant user and not writable by others.
- **Single writer on Windows.** On POSIX, the receipt log is locked with `fcntl`. Windows has no lock, so run one writer at a time there.
- **Statement logging.** With `log_statement = 'all'` (or similar) on the admin connection, the server log captures grant SQL, including the hash-key parameter and SCRAM verifiers. Disable statement logging for the datagrant admin role.
- **The view runs with the owner's rights.** Row-level security on the base table is not applied to the grantee through the view. The policy's row filters are the control.
- **One database per revoke.** `DROP OWNED` covers the current database only. datagrant grants within one database, so don't grant the temporary role anything elsewhere by hand.
- **`VALID UNTIL` is a backstop.** It blocks new logins but doesn't end open sessions. `sweep` does, so schedule it.
- **One key per log.** A receipt log is verified with one public key. Rotating the signing key means starting a new log.
- **Operators are trusted.** Anyone holding the admin DSN, the policy and the keys can read data directly or rewrite history. datagrant doesn't protect against them.
