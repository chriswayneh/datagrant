# CLI reference

```text
datagrant [--json] [--dsn DSN] [--signing-key FILE] [--hash-key FILE] [--receipt-log FILE] [--receipt-sink URL] [--receipt-sink-mode MODE] [--version] COMMAND ...
```

Run `datagrant COMMAND --help` for the exact flags of your installed version. This page matches v0.1.0.

## Conventions

- **Dry run by default.** Any command that changes something (`keys init`, `request`, `approve`, `revoke`, `sweep`, `preflight`) only reports what it would do unless you pass `--apply`. `--dry-run` is accepted as a no-op. Passing both `--apply` and `--dry-run` exits 2.
- **`--json`** gives machine-readable output and can go before or after the command.
- **Per-command flags.** Each command accepts only the shared flags it uses (see the table below). Using a flag a command doesn't take, for example `policy check --dsn ...`, exits 2.
- **Secrets are never echoed.** DSN passwords are redacted from errors. The one-time database password is printed once, to the person it belongs to.

## Environment and defaults

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Admin connection | `--dsn` | `DATAGRANT_DSN` | none (required where used) |
| Policy file | `--policy` | `DATAGRANT_POLICY` | none (required where used) |
| Signing key | `--signing-key` | `DATAGRANT_SIGNING_KEY` | `~/.config/datagrant/signing.key` |
| Hash key | `--hash-key` | `DATAGRANT_HASH_KEY` | `~/.config/datagrant/hash.key` |
| Receipt log | `--receipt-log` | `DATAGRANT_RECEIPT_LOG` | `~/.config/datagrant/receipts.jsonl` |
| External receipt sink (`https://` URL, or `file:///` path) | `--receipt-sink` | `DATAGRANT_RECEIPT_SINK` | none (no sink) |
| Sink mode (`required` or `best-effort`) | `--receipt-sink-mode` | `DATAGRANT_RECEIPT_SINK_MODE` | `best-effort` |
| Sink bearer token | none | `DATAGRANT_RECEIPT_SINK_TOKEN` | none |

Key paths resolve in this order: explicit flag, then environment variable, then `keys init --dir`, then the default directory. Every command uses the same resolver.

## Exit codes

| Code | Meaning |
| :---: | --- |
| 0 | Success, including a clean dry run and "nothing to do". |
| 1 | Denied or failed: policy denial, invalid policy, failed check, bad receipt chain, database error, or keys that already exist. |
| 2 | Usage error: unknown or inapplicable flag, an invalid receipt sink URL, mode or token, `--apply` with `--dry-run`, missing DSN or policy, or both keys resolving to the same file. |
| 3 | `revoke`/`sweep`: access was removed but a receipt could not be written. `request`/`approve` in `required` sink mode: the receipt could not be delivered to the sink, so the grant was revoked. `receipts push`: some receipts could not be delivered. |
| 4 | `revoke`/`sweep`: a revoke failed. The grant stays active and its role stays locked out; the error is in `last_error`. |

## Commands

### `keys init [--dir DIR] [--signing-key FILE] [--hash-key FILE] [--apply]`
Creates a random hash key and an ed25519 signing key as `0600` files and prints the public key. It refuses to overwrite an existing key (exit 1), and refuses if both paths are the same file (exit 2).

### `keys export-pubkey [--signing-key FILE]`
Prints the public key hex for `receipts verify --pubkey`.

### `policy check FILE`
Validates a policy offline. No database is involved.

### `request --dataset D --table SCHEMA.TABLE --columns C1,C2 --duration 2h --purpose TEXT [--row-filter EXPR] [--pending-ttl 24h] [--policy FILE] [--as-user NAME] [--apply]`
Evaluates the request against the policy. With `approval: auto`, `--apply` creates the masked view and an expiring LOGIN role, writes an `issued` receipt, and prints the connection details and the one-time password. With `approval: two-person`, it creates a pending request (default lifetime `--pending-ttl 24h`). The requester gets the password now, the database stores only its SCRAM verifier, and no role exists until approval. If the `issued` receipt can't be written, the grant is revoked at once ("no receipt, no access").

### `approve REQUEST_ID [--policy FILE] [--as-user NAME] [--apply]`
A member of an `approvers` group who is not the requester approves a pending request. The policy is re-evaluated at approval time.

### `grant list [--all]` and `grant status GRANT_ID`
Show active grants (`--all` includes revoked and expired) or one grant, including `last_error`.

### `revoke GRANT_ID [--apply]`
Locks the role out and commits, terminates its sessions, then drops the view and role and records the state. The revoke goes ahead even if the signing key is unavailable (exit 3 in that case).

### `sweep [--apply]`
Revokes every expired grant (`expired` receipts) and expires stale pending requests. Run it on a schedule, for example every minute.

### `receipts verify [--pubkey HEX|FILE] [--expect-head SHA256] [--sink URL] [--receipt-log FILE] [--signing-key FILE]`
Checks every signature, sequence number and hash link, and reports the first break. It prints the head hash. Record that hash somewhere off the host and pass it back with `--expect-head` to detect truncation of the newest entries.

With `--sink URL` (alias `--receipt-sink`, or `DATAGRANT_RECEIPT_SINK`), it also reads the sink head and compares it with the local chain. It never writes to the sink or the outbox cursor. Equal heads pass. A sink behind the local log passes if the local receipt at the sink's `seq` hashes to the sink head; the rest are reported as not yet delivered. A sink ahead of the local log, or a different hash at the same `seq`, fails (exit 1), as does a sink that can't be reached. It also fails if the sink head is behind the last `seq` the sink acknowledged in `<receipt-log>.sink` (sink lost or replaced), or if that cursor is unreadable, corrupt, or ahead of the local log. `--json` adds `sink_seq`, `sink_head_sha256` and `undelivered` (null when the sink check didn't produce them). If the local chain fails, the sink isn't checked.

### `preflight [--apply]`
Creates datagrant's state schema (with `--apply`) and warns about `PUBLIC` defaults that every grant role inherits: `CONNECT` on other databases, `TEMP` in this database, and `CREATE` in schema `public`. A dry run only reports the warnings.

### `receipts push [--receipt-sink URL] [--receipt-log FILE] [--apply]`
Sends receipts the sink hasn't acknowledged yet (the outbox) to the external sink, in order. A dry run shows how many are pending. The last acknowledged `seq` is kept in `<receipt-log>.sink` (0600). Run it from cron after a sink outage. Exit 3 if anything is still pending.

With a sink configured, `request` and `approve` send the `issued` receipt right after writing it locally. In `best-effort` mode a failed send only warns and leaves the receipt pending. In `required` mode the grant is revoked and the command exits 3. `revoke` and `sweep` remove access first and then make one delivery attempt without retries; a sink failure only warns and never changes their exit code. The token is never printed. See the [design](design/receipt-sink.md).

## Who can use which shared flag

| Command | `--dsn` | `--signing-key` | `--hash-key` | `--receipt-log` | `--receipt-sink` | `--receipt-sink-mode` | `--apply` |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `keys init` | | ✓ | ✓ | | | | ✓ |
| `keys export-pubkey` | | ✓ | | | | | |
| `policy check` | | | | | | | |
| `request`, `approve` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `grant list`, `grant status` | ✓ | | | | | | |
| `revoke`, `sweep` | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ |
| `receipts verify` | | ✓ | | ✓ | ✓ | | |
| `receipts push` | | | | ✓ | ✓ | | ✓ |
| `preflight` | ✓ | | | | | | ✓ |
