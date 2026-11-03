#!/usr/bin/env bash
# One-command datagrant demo.
#   ./scripts/demo.sh          start throwaway Postgres in Docker, run the demo, tear down
#   ./scripts/demo.sh down     remove the demo containers and volume
#   DATAGRANT_DEMO_DSN=... ./scripts/demo.sh   use an existing Postgres (no Docker)
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f scripts/demo-compose.yml)
PY="${PYTHON:-python3}"

down() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }

if [[ "${1:-}" == "down" ]]; then down; echo "demo containers and volume removed"; exit 0; fi

if [[ -n "${DATAGRANT_DEMO_DSN:-}" ]]; then
  exec "$PY" scripts/demo.py
fi

command -v docker >/dev/null || { echo "docker not found; set DATAGRANT_DEMO_DSN instead" >&2; exit 2; }
export DATAGRANT_DEMO_PG_PASSWORD="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(24))')"
export DATAGRANT_DEMO_PORT="${DATAGRANT_DEMO_PORT:-55439}"
trap down EXIT   # always remove containers + volume; demo.py removes temp keys itself
"${COMPOSE[@]}" up -d --wait
DATAGRANT_DEMO_DSN="postgresql://postgres:${DATAGRANT_DEMO_PG_PASSWORD}@127.0.0.1:${DATAGRANT_DEMO_PORT}/postgres" \
  "$PY" scripts/demo.py
