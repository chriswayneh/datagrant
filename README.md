<div align="center">

# datagrant

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/chriswayneh/datagrant/actions/workflows/ci.yml/badge.svg)](https://github.com/chriswayneh/datagrant/actions/workflows/ci.yml)

### Just-in-time, expiring access to regulated data, with receipts.

An open-source command-line tool that gives AI developers time-boxed, column- and row-limited, masked access to PHI/PII in Postgres, revokes it automatically, and issues a signed record of who saw what.

**Status:** Pre-alpha scaffolding. No release yet. Not for use with real regulated data. See the [roadmap](ROADMAP.md).

</div>

> **A note on this repo:** This GitHub account is my personal playground, where I experiment, learn, and build security tools in the open. Projects here are personal work, not a product or company offering.

---

## How it will work

```text
request (columns, rows, N hours, purpose)
  -> policy check (deny by default)
  -> expiring, masked Postgres view + role
  -> auto revoke
  -> signed JSON access receipt
```

Unlike system-level PAM (whole hosts or databases) or catalog rules (standing access), datagrant grants only the data slice you need, only for as long as you need it.

## Quick start (development)

```bash
git clone https://github.com/chriswayneh/datagrant
cd datagrant
pip install -e ".[dev]"
datagrant --version
ruff check . && mypy src && pytest -q
```

## How this project is built

datagrant follows the [AWS AI-DLC](https://github.com/awslabs/aidlc-workflows) workflow: Inception, Construction and Operations, each with a human approval gate. Artifacts live in [`aidlc-docs/`](aidlc-docs/).

- [ROADMAP.md](ROADMAP.md): milestones v0.1.0 to v1.0.0
- [roadmap/issues.yml](roadmap/issues.yml): every task with acceptance criteria
- [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md)

## License

[MIT](LICENSE)
