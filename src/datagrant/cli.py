"""Command-line entry point. Scaffolding only: no grant commands yet."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from datagrant import __version__


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="datagrant",
        description="Just-in-time, expiring, masked access to regulated data (scaffolding).",
    )
    parser.add_argument("--version", action="version", version=f"datagrant {__version__}")
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
