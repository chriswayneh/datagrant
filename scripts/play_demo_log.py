#!/usr/bin/env python3
"""Print a captured demo log slowly so VHS can record a readable GIF.

Usage:
    python3 scripts/play_demo_log.py FILE
    python3 scripts/play_demo_log.py --duration-only FILE
"""

from __future__ import annotations

import argparse
import sys
import time

LINE_DELAY = 0.028
STEP_DELAY = 0.28
MARKER_DELAY = 0.24
HOLD = 1.2
WRAP = 100


def wrap_line(line: str) -> list[str]:
    if len(line) <= WRAP:
        return [line]
    out: list[str] = []
    indent = "  "
    remaining = line
    first = True
    while remaining:
        width = WRAP if first else WRAP - len(indent)
        if len(remaining) <= width:
            out.append(remaining if first else indent + remaining)
            break
        cut = remaining.rfind(" ", 0, width)
        if cut < width // 3:
            cut = width
        chunk = remaining[:cut].rstrip()
        remaining = remaining[cut:].lstrip()
        out.append(chunk if first else indent + chunk)
        first = False
    return out


def lines_of(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    rows: list[str] = []
    for raw in text.splitlines():
        rows.extend(wrap_line(raw.rstrip("\n")))
    return rows


def delay_for(line: str) -> float:
    if line.startswith(("===", "# ")):
        return STEP_DELAY
    if line.startswith("DEMO MARKER") or line.strip() == "DEMO OK":
        return MARKER_DELAY
    return LINE_DELAY


def duration_seconds(path: str) -> float:
    return sum(delay_for(line) for line in lines_of(path)) + HOLD


def play(path: str) -> None:
    rows = lines_of(path)
    for line in rows:
        print(line, flush=True)
        time.sleep(delay_for(line))
    time.sleep(HOLD)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file")
    p.add_argument("--duration-only", action="store_true")
    args = p.parse_args()
    if args.duration_only:
        print(f"{duration_seconds(args.file):.2f}")
        return 0
    play(args.file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
