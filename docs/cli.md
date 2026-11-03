# CLI reference

```text
datagrant [--json] [--dsn DSN] [--signing-key FILE] [--hash-key FILE] [--receipt-log FILE] [--version] COMMAND ...
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

Key paths resolve in this order: explicit flag, then environment variable, then `keys init --dir`, then the default directory. Every command uses the same resolver.

## Exit codes

| Code | Meaning |
| :---: | --- |
| 0 | Success, including a clean dry run and "nothing to do". |
| 1 | Denied or failed: policy denial, invalid policy, failed check, bad receipt chain, database error, or keys that already exist. |
| 2 | Usage error: unknown or inapplicable flag, `--apply` with `--dry-run`, missing DSN or policy, or both keys resolving to the same file. |
| 3 | `revoke`/`sweep`: access was removed but a receipt could not be written. |
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

### `receipts verify [--pubkey HEX|FILE] [--expect-head SHA256] [--receipt-log FILE] [--signing-key FILE]`
Checks every signature, sequence number and hash link, and reports the first break. It prints the head hash. Record that hash somewhere off the host and pass it back with `--expect-head` to detect truncation of the newest entries.

### `preflight [--apply]`
Creates datagrant's state schema (with `--apply`) and warns about `PUBLIC` defaults that every grant role inherits: `CONNECT` on other databases, `TEMP` in this database, and `CREATE` in schema `public`. A dry run only reports the warnings.

## Who can use which shared flag

| Command | `--dsn` | `--signing-key` | `--hash-key` | `--receipt-log` | `--apply` |
| --- | :---: | :---: | :---: | :---: | :---: |
| `keys init` | | ✓ | ✓ | | ✓ |
| `keys export-pubkey` | | ✓ | | | |
| `policy check` | | | | | |
| `request`, `approve` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `grant list`, `grant status` | ✓ | | | | |
| `revoke`, `sweep` | ✓ | ✓ | | ✓ | ✓ |
| `receipts verify` | | ✓ | | ✓ | |
| `preflight` | ✓ | | | | ✓ |
