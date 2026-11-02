# Contributing to datagrant

Issues and pull requests are welcome. Keep changes small and focused, and describe what you changed and why in the pull request.

1. Pick a task from [ROADMAP.md](ROADMAP.md) whose dependencies are complete. Details are in [roadmap/issues.yml](roadmap/issues.yml).
2. Read the [working rules](AGENTS.md). Follow the [contributor rules](roadmap/README.md#contributor-rules) and the AI-DLC stage gates in [aidlc-docs/](aidlc-docs/).
3. Run `ruff check . && mypy src && pytest -q` before opening a PR.
4. Use fictional data only. Never commit real PHI/PII, credentials, or keys.
