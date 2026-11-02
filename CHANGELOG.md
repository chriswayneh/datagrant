# Changelog

## [Unreleased]
### Added
- Project scaffolding: package skeleton with `datagrant --version`, CI (lint, type, test), AI-DLC artifact folders, and the v0.1.0 to v1.0.0 roadmap.
- Policy file loader, schema validation, and allow/deny evaluator (`datagrant.policy`, U1); example `examples/policy.yaml`. Adds runtime dependency PyYAML.
- Postgres grant engine (U2): per-grant `security_barrier` view of allowed columns/rows, `LOGIN` role with `VALID UNTIL` and one-time password (SCRAM verifier sent, never plaintext), grant state table, safe row-filter grammar. Adds runtime dependency psycopg 3; CI adds bandit and a Postgres 16 integration job.
