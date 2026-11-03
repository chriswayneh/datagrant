<div align="center">

# datagrant

[![release](https://img.shields.io/github/v/release/chriswayneh/datagrant?style=flat&label=release)](https://github.com/chriswayneh/datagrant/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/chriswayneh/datagrant/actions/workflows/ci.yml/badge.svg)](https://github.com/chriswayneh/datagrant/actions/workflows/ci.yml)

### Temporary, masked access to sensitive data, with signed receipts.

An open source command line tool that gives developers short, limited access to PHI and PII in Postgres. Each grant covers only the columns and rows they need, masks sensitive values, ends automatically, and leaves a signed record of who saw what.

**Status:** [v0.1.0](https://github.com/chriswayneh/datagrant/releases/tag/v0.1.0) is released. Until version 1.0, commands and options may change. Use fictional or test data until you have reviewed the [security model](docs/security.md). See the [roadmap](ROADMAP.md).

</div>

> **A note on this repo:** This GitHub account is my personal playground, where I experiment, learn, and build security tools in the open. Projects here are personal work, not a product or company offering.

---

## See it in 60 seconds

```bash
git clone https://github.com/chriswayneh/datagrant && cd datagrant
pip install -e .
make demo        # temporary Postgres in Docker with fake patient data; cleans up after itself
```

The demo creates keys, checks a policy, gives alice a one-hour masked view of the west region only, runs a two-person approval, revokes it while she is still connected (her session is closed), sweeps an expired grant, and verifies the signed receipt chain. It ends with `DEMO OK`. No Docker? Point it at a scratch database with `DATAGRANT_DEMO_DSN=...`. See [docs/demo.md](docs/demo.md).

In the grantee's view, the identifying columns are redacted, hashed with a keyed HMAC, partially masked or NULL, and only `west` rows appear. Reading the raw table is denied.

## The problem

- **AI and data developers often get broad, permanent access** to production tables or full copies, because setting up narrow, temporary access by hand is slow.
- **That breaks the HIPAA "minimum necessary" rule** and data minimization rules for PII, and the only record of who saw what is usually a ticket.
- **datagrant makes narrow access the easy option.** Ask for specific columns and rows, for a set number of hours, with a reason. The policy decides, access ends on its own, and every step leaves a receipt you can verify.

## How it works

```mermaid
flowchart LR
    A[datagrant request<br/>columns, rows, duration, purpose] --> B{policy.yaml<br/>deny by default}
    B -- denied --> X[reasons, exit 1]
    B -- two-person --> P[pending request] --> AP[datagrant approve<br/>by someone else]
    B -- auto --> G
    AP --> G[masked security_barrier view<br/>+ LOGIN role, VALID UNTIL]
    G --> U[developer connects<br/>with one-time password]
    G --> R[revoke / sweep<br/>lock out, kill sessions, drop]
    G -. issued .-> S[(signed, hash-chained<br/>receipt log)]
    R -. revoked / expired .-> S
```

Every command that changes something is a **dry run unless you add `--apply`**.

## Install

Requires Python 3.11 or later and Postgres (tested on version 16). The `hash` mask also needs the `pgcrypto` extension. datagrant isn't on PyPI yet, so install it from GitHub:

```bash
pip install git+https://github.com/chriswayneh/datagrant.git
datagrant --version
```

## Quick start against your database

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

To run it in production (admin role, scheduling, keys and backups), see the [runbook](aidlc-docs/operations/runbook.md).

## Policy at a glance

```yaml
version: 1
approval: auto                 # or two-person (needs approvers)
approvers: [security]          # groups allowed to approve two-person requests
max_duration: 8h
groups:
  ml-team: [alice, bob]
  security: [carol]
datasets:
  - name: clinic
    database: clinicdb
    tables:
      - name: public.patients
        allowed_groups: [ml-team]
        max_duration: 4h
        columns:               # only listed columns can be requested
          patient_id: hash     # passthrough | redact | hash | partial | null
          zip: partial
          full_name: redact
          region: passthrough
        row_filters: ["region = 'west'"]
        require_row_filter: true
```

See the full [policy reference](docs/policy.md).

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
| `receipts verify` | Check every receipt signature and the hash chain |
| `preflight` | Set up datagrant's tables and warn about risky PUBLIC permissions |

Exit codes are `0` for success, `1` for denied or failed, `2` for a usage error, `3` when a receipt wasn't written, and `4` when a revoke failed. Add `--json` to any command for JSON output. See the full [CLI reference](docs/cli.md).

## Security model and honest limits

datagrant narrows and time-boxes access and makes it auditable. It is not an identity provider or a data loss prevention system. Read [docs/security.md](docs/security.md) before using it with real data. In short:

- **Identity is not authentication.** The requester is the operating system user, or whoever `--as-user` names. Anyone with the admin connection string can claim any name, so real two-person control needs datagrant behind a service that signs people in and holds that connection string.
- **Columns used in a row filter are visible** to the grantee, because a filter column must also be a listed column.
- **Masking still shows some shape.** You can see whether a value is empty, and partial and hash masks show its length.
- **Hashed values can be matched** across grants and datasets, because one hash key covers everything.
- **Deleting the newest receipts** is only caught if you saved the latest hash somewhere else and check it with `--expect-head`.
- **On Windows, the receipt log isn't locked,** so only one process should write to it at a time.
- **Full statement logging** (`log_statement = 'all'`) on the admin connection would record grant SQL, including key values. Turn it off for the datagrant admin role.

## Documentation

- [Policy reference](docs/policy.md)
- [CLI reference](docs/cli.md)
- [Security model](docs/security.md)
- [Operations](docs/operations.md)
- [Demo](docs/demo.md)
- [Changelog](CHANGELOG.md), [roadmap](ROADMAP.md), [security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md)

## How this project is built

datagrant follows the [AWS AI-DLC](https://github.com/awslabs/aidlc-workflows) workflow, which has three phases (Inception, Construction and Operations), each with a human approval step. Artifacts live in [`aidlc-docs/`](aidlc-docs/).

## License

MIT. See [LICENSE](LICENSE).
