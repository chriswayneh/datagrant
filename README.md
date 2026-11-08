<div align="center">

<img src="docs/assets/banner.svg" alt="datagrant: Temporary, masked access to PHI and PII in Postgres, with signed access receipts" width="100%">

[![release](https://img.shields.io/github/v/release/chriswayneh/datagrant?style=flat&label=release)](https://github.com/chriswayneh/datagrant/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/chriswayneh/datagrant/actions/workflows/ci.yml/badge.svg)](https://github.com/chriswayneh/datagrant/actions/workflows/ci.yml)

**Temporary, masked access to PHI and PII in Postgres, with signed access receipts.**

[Docs](docs/cli.md) · [Security](docs/security.md) · [Roadmap](ROADMAP.md) · [Releases](https://github.com/chriswayneh/datagrant/releases)

</div>

An open source command line tool that gives developers short, limited access to PHI and PII in Postgres. Each grant covers only the columns and rows they need, masks sensitive values, ends automatically, and leaves a signed record of who saw what.

**Status:** v0.3.0 is ready, release pending ([release notes](docs/release-notes/v0.3.0.md)); [v0.2.0](https://github.com/chriswayneh/datagrant/releases/tag/v0.2.0) is the latest published release. v0.2.0 changes `hash` outputs from v0.1.0; see those notes before upgrading from 0.1.x. Until version 1.0, commands and options may change. Use fictional or test data until you have reviewed the [security model](docs/security.md).

## Demo

<p align="center"><img src="docs/assets/demo.gif" alt="datagrant demo output: masked rows with a hidden filter column, per-dataset hashes, two-person approval, revoke, sweep, receipt verification and an external receipt sink catching a deleted receipt even after the local cursor is deleted, ending in DEMO OK" width="100%"></p>

Run it yourself. It needs Python 3.11 or later and Docker with the compose plugin:

```bash
git clone https://github.com/chriswayneh/datagrant && cd datagrant
pip install -e .
make demo          # temporary Postgres 16 in Docker with fake patient data
make demo-down     # only needed if a run was interrupted; the demo tears down on exit
```

The demo creates keys, checks a policy, gives alice a one-hour masked view of the west region only (filtered on `region` without showing it), shows the same SSN hashing differently in a second dataset, runs a two-person approval, revokes her grant while she is still connected, sweeps an expired grant, verifies the signed receipt chain, then pushes the receipts to a `file://` sink and shows `receipts verify --sink` catching a deleted local receipt, first through the local outbox cursor and then, with the cursor deleted too, from the sink itself (`sink is ahead`). Each step prints a `DEMO MARKER` line, and a successful run ends with `DEMO OK`.

No Docker? Point it at a scratch database (the demo drops and recreates the `dg_demo` schema):

```bash
DATAGRANT_DEMO_DSN=postgresql://admin:PASSWORD@localhost:5432/scratch ./scripts/demo.sh
```

See [docs/demo.md](docs/demo.md) for every step. The GIF above replays real output from the project's CI demo run.

## Features

Only features that ship in v0.3.0 (verified against the CLI and source):

- [x] **Deny-by-default policy.** One YAML file decides who can request what, and for how long. Unknown keys are errors; evaluation refuses anything not allowed explicitly.
- [x] **Narrow grants.**
  - [x] Column allow-list: only columns listed in the policy can be requested.
  - [x] Optional required row filters (the request must exactly match a policy entry).
  - [x] `filter_columns`: filter rows on a column without exposing it (v0.2.0).
  - [x] Five masking modes per column: `passthrough`, `redact`, keyed HMAC `hash`, `partial`, or `null`. Hashes are scoped per dataset (v0.2.0).
- [x] **Expiring Postgres access.**
  - [x] A masked `security_barrier` view plus a `LOGIN` role with `VALID UNTIL`.
  - [x] One-time password shown once; for two-person mode the database stores only the SCRAM verifier until approval.
  - [x] `datagrant sweep` revokes expired grants on a schedule.
- [x] **Revoke closes sessions.** Lock the role out (`NOLOGIN`), terminate its backends, then drop the view and role.
- [x] **Two-person approval.** A different person in an `approvers` group must approve; self-approval is refused. Policy is re-checked at approval time.
- [x] **OIDC identity** (v0.3.0). Optional `policy.identity.mode: oidc` verifies an ID token on `request` and `approve`. Default local mode still records the OS user or `--as-user`. See the [policy identity block](docs/policy.md#identity), [CLI](docs/cli.md#oidc-identity) and the [OIDC request and approve demo](docs/demo-oidc.md).
- [x] **Signed, hash-chained receipts.** ed25519 signatures in an append-only JSONL log. Verify with `datagrant receipts verify` (optional `--expect-head` to catch truncation).
- [x] **External receipt sink** (v0.2.0). Copy every receipt to an HTTPS webhook or an append-only file elsewhere, with an outbox and `receipts push` for outages, an optional `required` mode, and `receipts verify --sink` to catch local truncation or rewrites.
- [x] **Dry run by default.** Every command that changes something reports what it would do and changes nothing unless you pass `--apply`.
- [x] **Honest CLI exit codes.** `0` ok, `1` denied or failed, `2` usage, `3` receipt not written, not delivered to the sink, or unusable outbox, `4` revoke failed. Add `--json` for machine-readable output.

## Architecture

Flow of a grant: **request -> policy -> masked view + expiring role -> receipt log -> revoke/sweep**.

```mermaid
flowchart LR
    A[request<br/>columns, rows, duration, purpose] --> B{policy.yaml<br/>deny by default}
    B -- denied --> X[reasons, exit 1]
    B -- two-person --> P[pending request] --> AP[approve<br/>by someone else]
    B -- auto --> G
    AP --> G[masked security_barrier view<br/>+ LOGIN role, VALID UNTIL]
    G --> U[developer connects<br/>one-time password]
    G -. issued .-> S[(signed hash-chained<br/>receipt log)]
    G --> R[revoke / sweep<br/>NOLOGIN, kill sessions, drop]
    R -. revoked / expired .-> S
    S --> V[receipts verify]
```

Every mutating command is a **dry run unless you add `--apply`**. On issue, if the receipt cannot be written, the grant is revoked at once.

## Quick start

Requires Python 3.11 or later and Postgres (tested on version 16). The `hash` mask also needs the `pgcrypto` extension. datagrant isn't on PyPI yet, so install it from GitHub:

```bash
pip install git+https://github.com/chriswayneh/datagrant.git
datagrant --version
```

Then run it against your database:

```bash
export DATAGRANT_DSN='postgresql://datagrant_admin@db.internal/clinicdb'   # password via ~/.pgpass
export DATAGRANT_POLICY=policy.yaml
datagrant keys init --apply            # hash + signing keys, 0600, ~/.config/datagrant
datagrant policy check policy.yaml
datagrant preflight --apply            # create datagrant state; warn on risky PUBLIC defaults
datagrant request --dataset clinic --table public.patients --columns patient_id,zip \
  --row-filter "region = 'west'" --duration 2h --purpose "debug model drift"          # dry run
datagrant request ... --apply          # prints connection info + one-time password, once
datagrant sweep --apply                # run every minute from cron/systemd
datagrant receipts verify
```

See the [policy reference](docs/policy.md) for the policy format and the [runbook](aidlc-docs/operations/runbook.md) for production setup.

## CLI at a glance

| Command | What it does |
| --- | --- |
| `keys init`, `keys export-pubkey` | Create the hash and signing keys, or print the receipt public key |
| `policy check FILE` | Check a policy file offline |
| `request` | Ask for access, granted right away or held for a second approver |
| `approve REQUEST_ID` | Approve a pending request (must be a different person in an approver group) |
| `grant list`, `grant status ID` | List grants or show one grant |
| `revoke GRANT_ID` | End access now and close open sessions |
| `sweep` | Revoke expired grants and expire old requests |
| `receipts verify` | Check every receipt signature and the hash chain; with `--sink`, compare against the external sink |
| `receipts push` | Send receipts still pending in the outbox to the external sink |
| `preflight` | Set up datagrant's tables and warn about risky PUBLIC permissions |

Exit codes are `0` for success, `1` for denied or failed, `2` for a usage error, `3` when a receipt wasn't written, wasn't delivered to the sink, or the outbox is unusable, and `4` when a revoke failed. Add `--json` to any command for JSON output. See the full [CLI reference](docs/cli.md).

## Limits

datagrant narrows and time-boxes access and makes it auditable. It is not an identity provider or a data loss prevention system. Read [docs/security.md](docs/security.md) before using it with real data. In short:

- **Identity depends on the policy.** Default local mode records the OS user or `--as-user` and is not authentication. Optional `identity.mode: oidc` (v0.3.0) verifies an ID token on `request` and `approve`. Anyone who holds the admin connection string can still bypass datagrant. See [docs/security.md](docs/security.md).
- **Row filters reveal what they match.** A column listed only in `filter_columns` is hidden, but the grantee knows every row matches the filter.
- **Masking still shows some shape.** You can see whether a value is empty (NULL stays NULL under `partial` and `hash`), and `partial` keeps its length.
- **Hashed values can be matched** across grants on the same dataset (or datasets sharing a `hash_scope`), but not across datasets.
- **Deleting the newest receipts** is only caught with an external receipt sink and `receipts verify --sink` (v0.2.0), or if you saved the latest hash somewhere else and check it with `--expect-head`. Receipts not yet delivered to the sink can't be checked off-host.
- **On Windows, the receipt log, the file sink and outbox flushes aren't locked,** so only one process should write at a time.
- **Full statement logging** (`log_statement = 'all'`) on the admin connection would record grant SQL, including key values. Turn it off for the datagrant admin role.

## Documentation

- [Policy reference](docs/policy.md)
- [CLI reference](docs/cli.md)
- [Security model](docs/security.md)
- [Operations](docs/operations.md)
- [Demo](docs/demo.md) and [OIDC request and approve demo](docs/demo-oidc.md)
- [Changelog](CHANGELOG.md), [roadmap](ROADMAP.md) and [security policy](SECURITY.md)

## Contributing

Issues and pull requests are welcome. Keep changes small and focused, run `ruff check . && mypy src && pytest -q` before opening a PR, and use fictional data only. See the [contributing guide](CONTRIBUTING.md).

## How this project is built

datagrant follows the [AWS AI-DLC](https://github.com/awslabs/aidlc-workflows) workflow, which has three phases (Inception, Construction and Operations), each with a human approval step. Artifacts live in [`aidlc-docs/`](aidlc-docs/).

## License

MIT. See [LICENSE](LICENSE).
