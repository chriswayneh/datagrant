# Roadmap working guide

The [roadmap overview](../ROADMAP.md) is the readable summary of what has shipped. [Task definitions](issues.yml) hold early planning (why, files, acceptance, size, dependencies). Treat `ROADMAP.md` as current; `issues.yml` is historical and does not list M4.

**v0.6.0 is released** (tag `v0.6.0`, 2026-11-14). M4 Snowflake warehouses shipped: grant, approve, revoke, sweep, masks, row filters, catalog inspect, key-pair-only DSN. Notes: [docs/release-notes/v0.6.0.md](../docs/release-notes/v0.6.0.md). Product README: [../README.md](../README.md).

**Next after M4:** BigQuery, target v0.7.0+. M5 Inception is in progress. Design pending approval: [docs/design/bigquery.md](../docs/design/bigquery.md). Rate limits, `max_rows`, and break-glass stay out.

Update task status in `issues.yml` and the overview in the same PR as the work. Mark a version released only after the maintainer publishes it.

## Contributor rules

1. One task = one branch `<type>/<task-id>-<slug>` = one small PR against `main`. Don't bundle tasks.
2. Never force-push, rebase, or rewrite history. Fix review feedback with new commits.
3. The maintainer merges after review passes on the exact head commit (code PRs also need a security review).
4. Never change repo visibility, settings, branch protection, or secrets. Only the maintainer creates tags and releases.
5. Every PR must pass: `ruff check . && mypy src && pytest -q && git diff --check`. Paste the output in the PR body.
6. The PR body includes the task id, what changed, acceptance results, and a CHANGELOG `[Unreleased]` entry for user-visible changes.
7. Follow AI-DLC: update the matching artifact in `aidlc-docs/`, append an entry to `aidlc-docs/audit.md`, and don't start a new stage until its approval gate is signed off.
8. Non-goals: no SaaS, no telemetry, no standing access. Fictional data only in tests and examples.

## Release checklist

1. All milestone tasks are merged and CI is green on `main`.
2. `pyproject.toml` and `src/datagrant/__init__.py` versions match the target.
3. CHANGELOG `[Unreleased]` moved under the new version with today's date.
4. README status and SECURITY.md updated. Every README matches the shipped version (install, CLI, feature list, relative links).
5. AI-DLC gate for the stage approved in `aidlc-docs/audit.md`.
6. Secrets scan clean.
7. Maintainer creates the tag and GitHub release.
