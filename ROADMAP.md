# Roadmap

Where datagrant is going, and what is ready to work on.

**Current release:** none. **Next release:** v0.1.0 scaffolding. Milestones and scope may change.

Each milestone maps to an AI-DLC stage (see [`aidlc-docs/`](aidlc-docs/)). A stage starts only after the previous stage's human approval gate is logged in [`aidlc-docs/audit.md`](aidlc-docs/audit.md).

## Milestones

| Milestone | Version | Theme | Status | Tasks |
| --- | --- | --- | --- | :---: |
| M0 | v0.1.0 | Scaffolding and AI-DLC Inception | Planned | 4 |
| M1 | v0.2.0 | Construction: design and grant model | Planned | 4 |
| M2 | v0.3.0 | Construction: Postgres grants | Planned | 4 |
| M3 | v0.4.0 | Construction: masking | Planned | 3 |
| M4 | v0.5.0 | Construction: signed access receipts | Planned | 3 |
| M5 | v0.9.0 | Operations and API freeze | Planned | 4 |
| M6 | v1.0.0 | Stable release | Planned | 3 |

**25 tasks, all planned.** Full details (why, files, acceptance, size, dependencies) are in [`roadmap/issues.yml`](roadmap/issues.yml). Contributor rules and the release checklist are in the [working guide](roadmap/README.md).

---

## v0.1.0: Scaffolding and AI-DLC Inception

Repo skeleton, CI, Inception artifacts approved.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `I-1` | Technical design document and execution plan; approve Inception | S | — |
| `I-2` | User stories and personas | S | I-1 |
| `I-3` | Units of work | S | I-2 |
| `I-4` | Release v0.1.0 scaffolding | S | I-3 |

---

## v0.2.0: Construction: design and grant model

Designs, NFRs and the grant/policy data model.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `D-1` | Functional design: grant request schema | M | I-3 |
| `D-2` | NFR requirements and design | M | D-1 |
| `D-3` | Grant request parser and validator | M | D-1 |
| `D-4` | Policy file and offline policy check | M | D-3 |

---

## v0.3.0: Construction: Postgres grants

Create and revoke expiring, column/row limited Postgres access.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `P-1` | Postgres connector and test harness | M | D-4 |
| `P-2` | Create scoped view and temporary role | L | P-1 |
| `P-3` | Revoke and expiry sweep | M | P-2 |
| `P-4` | Grant state store | S | P-2 |

---

## v0.4.0: Construction: masking

Presidio-based masking of PHI/PII in granted views.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `K-1` | Masking policy model | M | P-2 |
| `K-2` | Presidio integration (optional extra) | L | K-1 |
| `K-3` | Masked view generation | M | K-1 |

---

## v0.5.0: Construction: signed access receipts

Tamper-evident record of who saw what.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `R-1` | Receipt schema | S | P-3 |
| `R-2` | Ed25519 signing and verify | M | R-1 |
| `R-3` | Postgres audit correlation | M | R-2 |

---

## v0.9.0: Operations and API freeze

Docs, runbooks, threat model, packaging.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `O-1` | Operations runbook | M | R-2 |
| `O-2` | Threat model and security review | M | O-1 |
| `O-3` | CLI and schema freeze | S | O-2 |
| `O-4` | Packaging and reproducible build | M | O-3 |

---

## v1.0.0: Stable release

Release candidate proven from a fresh install.

| ID | Task | Size | Depends on |
| --- | --- | :---: | --- |
| `V-1` | Fresh-install end-to-end test | M | O-4 |
| `V-2` | Final docs and AI-DLC audit close-out | S | V-1 |
| `V-3` | Release v1.0.0 | S | V-2 |

---

## Principles

- CLI only, Postgres first. No SaaS, no telemetry.
- Deny by default; fail closed on revoke errors.
- Never log or store regulated data values. Fictional data only in tests and examples.
- Time-boxed, column/row-scoped grants instead of standing access.
