#!/usr/bin/env bash
# Re-record README/docs GIFs from real CLI output.
#   Postgres: needs DATAGRANT_DEMO_DSN (scratch DB; demo drops schema dg_demo).
#   Snowflake: dry-run only, no DSN.
# Tools: vhs, ttyd, ffmpeg, gifsicle, python3, datagrant.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PATH="${HOME}/go/bin:/usr/local/bin:${PATH}"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 2; }; }
need python3
need vhs
need ttyd
need ffmpeg
need gifsicle
need datagrant

sanitize() {
  # redact temp dirs; keep fictional patient rows and hashes
  sed -E \
    -e 's|/tmp/datagrant-demo-[A-Za-z0-9._-]+|<tmp>|g' \
    -e 's|/tmp/datagrant-sf-demo-[A-Za-z0-9._-]+|<tmp>|g' \
    -e 's|/tmp/tmp[A-Za-z0-9._-]+|<tmp>|g'
}

compress_gif() {
  local src="$1"
  local tmp
  tmp="$(mktemp --suffix=.gif)"
  gifsicle -O3 --lossy=80 --colors 96 -o "$tmp" "$src"
  mv "$tmp" "$src"
  local bytes
  bytes="$(wc -c < "$src")"
  if [[ "$bytes" -gt 2800000 ]]; then
    gifsicle -O3 --lossy=140 --colors 64 -o "$tmp" "$src"
    mv "$tmp" "$src"
    bytes="$(wc -c < "$src")"
  fi
  if [[ "$bytes" -gt 3000000 ]]; then
    echo "GIF still over 3 MB: $src ($bytes bytes)" >&2
    exit 1
  fi
  echo "wrote $src ($(python3 -c "print(round($bytes/1024/1024, 2))") MB)"
}

record_one() {
  local log="$1" tape="$2" gif="$3" title="$4"
  local secs
  secs="$(python3 scripts/play_demo_log.py --duration-only "$log")"
  # small buffer so VHS does not cut the last frame
  secs="$(python3 -c "print(round(float('$secs') + 1.2, 2))")"
  local run
  run="$(mktemp --suffix=.tape)"
  ROOT="$ROOT" SLEEP="${secs}s" LOG="$log" GIF="$gif" python3 - "$tape" "$run" <<'PY'
import os, shlex, sys
src, dest = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
text = text.replace("__SLEEP__", os.environ["SLEEP"])
text = text.replace("__LOG__", os.environ["LOG"])
text = text.replace("__GIF__", os.environ["GIF"])
text = text.replace("__ROOT__", shlex.quote(os.environ["ROOT"]))
open(dest, "w", encoding="utf-8").write(text)
PY
  echo "recording $gif (${secs}s, $title)"
  vhs "$run"
  rm -f "$run"
  compress_gif "$gif"
}

WORKDIR="$(mktemp -d /tmp/datagrant-gif-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "# datagrant postgres demo, v0.6.0 (real CLI output)" > "$WORKDIR/postgres.log"
if [[ -z "${DATAGRANT_DEMO_DSN:-}" ]]; then
  echo "set DATAGRANT_DEMO_DSN to a scratch Postgres to refresh demo.gif" >&2
  exit 2
fi
python3 scripts/demo.py >> "$WORKDIR/postgres.log" 2>/dev/null
grep -q '^DEMO OK$' "$WORKDIR/postgres.log"
sanitize < "$WORKDIR/postgres.log" > "$WORKDIR/postgres.clean.log"
grep -E 'BEGIN PRIVATE|SCRAM-SHA-256' "$WORKDIR/postgres.clean.log" && {
  echo "refusing to record: secret-looking text in postgres log" >&2
  exit 1
}

python3 scripts/demo_snowflake.py > "$WORKDIR/snowflake.log"
grep -q '^DEMO OK$' "$WORKDIR/snowflake.log"
sanitize < "$WORKDIR/snowflake.log" > "$WORKDIR/snowflake.clean.log"
grep -E 'BEGIN PRIVATE|snowflake://|private_key_file=' "$WORKDIR/snowflake.clean.log" && {
  echo "refusing to record: secret-looking text in snowflake log" >&2
  exit 1
}

record_one "$WORKDIR/postgres.clean.log" docs/assets/demo.tape docs/assets/demo.gif "postgres"
record_one "$WORKDIR/snowflake.clean.log" docs/assets/demo-snowflake.tape docs/assets/demo-snowflake.gif "snowflake"
