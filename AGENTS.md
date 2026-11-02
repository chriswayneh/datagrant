# Working rules (AWS AI-DLC)

These rules apply to every contributor, human or automated. They follow the [AWS AI-DLC](https://github.com/awslabs/aidlc-workflows) methodology used in [`aidlc-docs/`](aidlc-docs/).

## 1. Phase 1: Inception

- Do not write any code yet.
- Review the repository structure and the project goal ([vision](aidlc-docs/inception/vision.md), [requirements](aidlc-docs/inception/requirements.md)).
- Produce a [application design document](aidlc-docs/inception/application-design.md) and an [execution plan](aidlc-docs/inception/execution-plan.md).
- Wait for the maintainer's explicit approval, recorded in [`aidlc-docs/audit.md`](aidlc-docs/audit.md), before starting Construction.

## 2. Phase 2: Construction

- Start only after the Inception approval is logged.
- Write code in small, modular chunks: one roadmap task per PR (see [ROADMAP.md](ROADMAP.md)).
- Every chunk ships with a comprehensive test suite covering normal, edge, and failure cases.

## 3. Guardrails

Check all code against security best practices before presenting it for review:

- **Secrets:** no credentials, keys, or tokens in code, tests, logs, or history.
- **Input validation:** validate and bound all external input; fail with clear errors.
- **Least privilege:** grant only the access needed, for the shortest time; fail closed.
- **SQL injection:** parameterize queries and quote identifiers; never build SQL from raw input.
- **Dependency risk:** add dependencies sparingly, pin them, and review for known vulnerabilities.
- **Regulated data:** never log or store PHI/PII values; use fictional data only.

Also follow the [contributor rules](roadmap/README.md#contributor-rules).
