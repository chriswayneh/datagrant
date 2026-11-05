# Design: external receipt sink

Status: implemented on main (unreleased), in PRs #18, #19 and #20, documented in a follow-up docs PR. Differences from this proposal: `receipts push` is a dry run unless `--apply`, like the other commands that change things; `request` and `approve` also refuse (exit 3) when the outbox cursor is unusable; and `verify --sink` also fails when the sink is behind its own acknowledgements or the cursor is bad. The [CLI reference](../cli.md#receipt-sink) is authoritative. Roadmap item: [External receipt sink](../../ROADMAP.md).

## Problem

Receipts live in one local JSONL file (`$DATAGRANT_RECEIPT_LOG`, default under `~/.config/datagrant`). Each line is signed with ed25519 and carries `seq` and `prev_receipt_sha256`, so `receipts verify` catches any edited, reordered, inserted or deleted line in the middle of the log.

It can't catch a change to the tail. Someone with write access to the host can:

- **truncate** the newest receipts, leaving a valid shorter chain;
- **replace** the file with an older copy;
- **rewrite** the tail, if they also hold the signing key (re-signing is then indistinguishable from honest history).

Today only `receipts verify --expect-head <sha256>` catches the first two, and only if a person recorded the head hash somewhere else earlier. The goal is to make that copy automatic: every receipt also goes to a store the host can't rewrite, and `verify` compares the two.

Out of scope: protecting against an operator who holds the admin DSN and the keys and also controls the sink. See [Security limits](#security-limits).

## Options weighed

| Option | Tamper resistance | Dependencies | Ops cost | Verdict |
| --- | --- | --- | --- | --- |
| Append-only file on another host (NFS or SSHFS mount with `chattr +a`, or a log shipper) | Good only if the mount is append-only and the remote host is separately administered | None in datagrant | Medium: mounts, permissions | Supported for free by a file sink, not the main path |
| S3 Object Lock or another WORM bucket | Strong: retention enforced by the provider | boto3 or a hand-rolled SigV4 client | Medium: bucket, IAM, retention | Best evidence store, but a heavy dependency. Reachable through the webhook (a small receiver writes to the bucket) |
| syslog | Weak: UDP loses lines, no read-back for verify | Stdlib | Low | Rejected: no way to read the head back |
| HTTPS webhook | As strong as the receiver (SIEM, log service, function writing to WORM storage) | Stdlib `urllib` and `ssl` only | Low | **Recommended built-in** |
| Postgres table owned by another role | Good if that role is not reachable with the admin DSN | psycopg (already a dependency) | Low to medium | Deferred: often the same server and the same administrators, so weaker in practice than it looks |

## Recommendation (v0.3.0)

1. Add a small **pluggable sink interface** in datagrant (`deliver(line)` and `head()`), selected by URL scheme.
2. Ship **one built-in sink: HTTPS webhook** on the standard library. It POSTs each signed receipt line and reads the remote head back. Any SIEM, log service or WORM bucket sits behind a receiver the user controls.
3. The local JSONL log stays the primary record. The sink is an off-host copy that `verify` checks against. No new runtime dependencies.

A `file://` sink (append to a path, intended for a remote append-only mount) is cheap to add with the interface and is useful in tests, so it ships in the same PR.

## Sink interface

```python
class ReceiptSink(Protocol):
    name: str
    def deliver(self, line: bytes) -> None: ...          # raise SinkError on failure
    def head(self) -> tuple[int, str] | None: ...         # (seq, sha256 of last line) or None if empty
```

- `line` is the exact signed bytes written locally (without the trailing newline). The sink never sees anything that isn't already in the local log: no passwords, no key material.
- `deliver` must be idempotent per `seq`: sending the same line twice is fine; a different line with an already-seen `seq` must be refused by the receiver (this is what makes a rewrite visible).

### Webhook contract

- `POST <url>` with `Content-Type: application/x-ndjson`, body = one or more receipt lines. Success is any 2xx.
- `GET <url>/head` returns `{"seq": <int>, "head_sha256": "<hex>"}`, or 404 if empty.
- HTTPS only (plain `http://` refused except `http://127.0.0.1` and `http://localhost`, for tests). Certificates verified with the system store; no option to turn verification off.
- Optional bearer token from the environment (below). Timeouts: 5 s connect, 10 s total per request.
- The receiver should check the signature with the exported public key (`datagrant keys export-pubkey`) and the chain link before storing. A reference receiver is a later, optional example, not part of datagrant.

## Delivery semantics

The rule "no receipt, no access" stays, and it stays about the **local** log: if the local `issued` receipt can't be written, the grant is revoked, exactly as today.

For the sink there is a mode setting:

| Mode | `issued` | `revoked`, `expired`, `revoke_failed` |
| --- | --- | --- |
| `required` | Delivered synchronously after the local write. If delivery fails after retries, the grant is revoked (with a local `revoked` receipt queued for the sink) and the command exits 3. | Never blocks the revoke. Failed delivery goes to the outbox. |
| `best-effort` (default) | Delivered synchronously; on failure the line goes to the outbox and the command prints a warning. The grant stands. | Same: outbox on failure. |

Revoke never waits on the sink. Removing access is always more important than recording it off-host.

### Retry and outbox

- Synchronous attempts: 3 tries with short backoff (0.5 s, 1 s, 2 s), total under about 15 s.
- The outbox is not a second file of record. It is just the local log plus a cursor: a small `<receipt-log>.sink` state file (0600, no symlinks, same rules as the log) holding the last `seq` the sink acknowledged.
- Every command that writes receipts, and `sweep`, first flushes anything after the cursor, in `seq` order. Delivery is in order, so the receiver can check the chain.
- A new `datagrant receipts push` command flushes the outbox on demand, for a cron job or after an outage.

## Configuration

Sink settings are runtime config, not policy: the policy describes access, and must never hold secrets or endpoints that change per host.

| Setting | CLI flag | Environment |
| --- | --- | --- |
| Sink URL (`https://...` or `file:///...`) | `--receipt-sink` | `DATAGRANT_RECEIPT_SINK` |
| Mode | `--receipt-sink-mode required\|best-effort` | `DATAGRANT_RECEIPT_SINK_MODE` |
| Bearer token | none (never on the command line) | `DATAGRANT_RECEIPT_SINK_TOKEN` |

The flags join the shared receipt flags (the same commands that accept `--receipt-log`). No sink configured means today's behavior, unchanged. The token is never logged, never written into receipts, and redacted from error messages the same way DSN passwords are. A URL with embedded credentials (`https://user:pass@...`) is refused.

## Verify

`receipts verify` gains `--sink` (or uses `DATAGRANT_RECEIPT_SINK`):

1. Verify the local log as today (signatures, chain, optional `--expect-head`).
2. Fetch the sink head `(seq, head_sha256)`.
3. Compare:
   - same `seq` and hash: OK;
   - remote `seq` greater than local: **local log truncated or replaced**: fail;
   - same `seq`, different hash: **local or remote rewritten**: fail;
   - remote `seq` smaller and the local line at that `seq` hashes to the remote head: OK with a note "N receipts not yet delivered" (outbox pending). A different hash there is a fail.
4. `--json` adds `sink_seq`, `sink_head_sha256` and `undelivered` to the result.

`--expect-head` keeps working and can be combined with `--sink`.

## Failure modes and exit codes

No new exit codes; the existing ones keep their meanings ([CLI exit codes](../cli.md)).

| Situation | Behavior | Exit |
| --- | --- | :---: |
| Sink config invalid (bad scheme, credentials in URL, unknown mode) | Refused before any database work | 2 |
| `issued` delivery fails, mode `best-effort` | Grant stands, line kept in outbox, warning on stderr | 0 |
| `issued` delivery fails, mode `required` | Grant revoked, outbox keeps the lines | 3 |
| Revoke receipt delivery fails | Revoke completes, outbox keeps the line, warning | unchanged (0, or 4 if the revoke itself failed) |
| `receipts push` can't deliver | Cursor unchanged | 3 |
| `verify --sink`: head mismatch or remote ahead | Reports where the chains split | 1 |
| `verify --sink`: sink unreachable | Reports that the remote check could not run; local result still printed | 1 |
| Sink state file corrupt or not private | Treated like a bad receipt log: refuse to write | 3 |

## Security limits

- **The sink is only as trustworthy as its receiver.** A webhook that accepts rewrites, or a bucket without retention, adds little. Use a store the datagrant host can't modify or delete from.
- **Delay window.** In `best-effort` mode an attacker who controls the host can delete outbox lines before they are pushed. `required` closes this for `issued` receipts only.
- **The signing key still matters.** Someone with the signing key and the sink token can send forged receipts for future `seq` values. The sink proves what was sent, not that it was true.
- **The token is a secret.** Anyone holding it can append to the sink (not rewrite, if the receiver refuses reused `seq`). Store it like the DSN.
- **Availability.** `required` mode makes grants depend on the sink being up. Revokes never do.
- **Operators are still trusted.** Someone who controls the host, the keys and the sink can rewrite everything. Keep the sink under separate administration.

## Follow-up PRs

Each one is small, with tests and docs, and gets the usual review.

1. **Sink interface plus webhook and file sinks.** `ReceiptSink`, URL parsing and validation, stdlib HTTPS client with timeouts and retries, token from env with redaction, `file://` sink, unit tests against a local test server.
2. **Delivery and outbox.** Wire delivery into grant, approve, revoke and sweep; sink mode; the `.sink` cursor file; `receipts push`; tests for `required` revoking on failure and for revoke never blocking.
3. **Verify integration.** `receipts verify --sink`, head comparison, `--json` fields, tests for truncation, replacement and pending deliveries.
4. **Docs.** `docs/cli.md`, `docs/security.md` (update the tail-truncation limit), `docs/operations.md` (running a receiver, cron for `receipts push`), CHANGELOG, ROADMAP.
