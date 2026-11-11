"""Session-level advisory lock for mutating ``--apply`` (M3).

The CLI connects with ``autocommit=True``, and ``approve`` counts the
concurrent-grant cap in one transaction then calls ``apply_plan`` in later
ones. ``pg_advisory_xact_lock`` is released at COMMIT and cannot cover that
window. This module takes ``pg_advisory_lock`` (session-scoped) on a
documented bigint constant and releases it with ``pg_advisory_unlock`` in a
``finally`` block. Session close is the backstop if the process dies first.

Do not derive the key from ``hashtext()`` or any SQL hash.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg

# Documented bigint; 'dgt' + 0x01. Must match docs/design/ops-hardening.md.
DATAGRANT_ADVISORY_LOCK_KEY = 0x64677401  # 1684501505

_LOCK_SQL = "SELECT pg_catalog.pg_advisory_lock(%s)"
_UNLOCK_SQL = "SELECT pg_catalog.pg_advisory_unlock(%s)"


def acquire_advisory_lock(conn: psycopg.Connection) -> None:
    """Take the session lock. Blocks until the previous holder unlocks or disconnects."""
    conn.execute(_LOCK_SQL, (DATAGRANT_ADVISORY_LOCK_KEY,))


def release_advisory_lock(conn: psycopg.Connection) -> None:
    """Drop the session lock. A closed session is the backstop; errors are swallowed."""
    if getattr(conn, "closed", 0):
        return
    try:
        conn.execute(_UNLOCK_SQL, (DATAGRANT_ADVISORY_LOCK_KEY,))
    except Exception:  # noqa: BLE001 - session close releases the lock
        return


@contextmanager
def holding_advisory_lock(conn: psycopg.Connection) -> Iterator[None]:
    """``pg_advisory_lock`` for the body; ``pg_advisory_unlock`` in ``finally``."""
    acquire_advisory_lock(conn)
    try:
        yield
    finally:
        release_advisory_lock(conn)
