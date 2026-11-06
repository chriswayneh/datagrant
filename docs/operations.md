# Operations

The full runbook lives in the AI-DLC operations artifacts: [aidlc-docs/operations/runbook.md](../aidlc-docs/operations/runbook.md). It covers:

- **Database hardening before the first grant.** Revoke risky `PUBLIC` defaults (run `datagrant preflight` to list them) and install `pgcrypto` if you use `hash` masks.
- **The admin role.** It must be able to end grantee sessions (`pg_signal_backend` unless it's a superuser). Otherwise revoke and sweep fail closed. Disable statement logging for it.
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

## OIDC identity (on main, pending v0.3.0)

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
