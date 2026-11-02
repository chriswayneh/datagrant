# AI-DLC artifacts

datagrant follows the [AWS AI-Driven Development Life Cycle](https://github.com/awslabs/aidlc-workflows): Inception (what and why), Construction (how), Operations (run it). Each stage ends with a human approval gate.

| Stage | Folder | Roadmap | Gate |
| --- | --- | --- | --- |
| Inception | [inception/](inception/) | v0.1.0 | Maintainer approves vision, requirements, stories, units |
| Construction | [construction/](construction/) | v0.2.0 to v0.5.0 | Maintainer approves design and NFRs per unit before code; test plan before release |
| Operations | [operations/](operations/) | v0.9.0 to v1.0.0 | Maintainer approves runbook and threat model |

- [aidlc-state.md](aidlc-state.md) tracks the current stage.
- [audit.md](audit.md) is the append-only log of decisions and approvals.

Working rules: see [AGENTS.md](../AGENTS.md).

Rules: propose, then wait for approval; record every approval in `audit.md`; never skip a gate.
