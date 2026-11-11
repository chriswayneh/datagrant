"""Session-level advisory lock for mutating ``--apply`` (M3).

The CLI connects with ``autocommit=True``, and ``approve`` counts the
concurrent-grant cap in one transaction then calls ``apply_plan`` in later
ones. ``pg_advisory_xact_lock`` is released at COMMIT and cannot cover that
window. Access-creating ``--apply`` takes ``pg_advisory_lock`` (session-scoped)
on a documented bigint constant, with ``lock_timeout`` so a CONNECT role that
holds the key cannot block forever. ``revoke`` / ``sweep`` use
``pg_try_advisory_lock`` and proceed without the lock on contention. Unlock
is ``pg_advisory_unlock`` in a ``finally`` block when this session acquired
it. Session close is the backstop if the process dies first.

``PUBLIC`` can ``EXECUTE pg_advisory_lock``; the lock is a coordination aid,
not a security boundary.

Do not derive the key from ``hashtext()`` or any SQL hash.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.errors import LockNotAvailable, QueryCanceled

# Documented bigint; 'dgt' + 0x01. Must match docs/design/ops-hardening.md.
DATAGRANT_ADVISORY_LOCK_KEY = 0x64677401  # 1684501505

# Access-creating --apply waits this long, then fail closed. Tests patch this.
LOCK_WAIT_SECONDS = 30.0

_LOCK_SQL = "SELECT pg_catalog.pg_advisory_lock(%s)"
_TRY_SQL = "SELECT pg_catalog.pg_try_advisory_lock(%s)"
_UNLOCK_SQL = "SELECT pg_catalog.pg_advisory_unlock(%s)"
_HOLDERS_SQL = (
    "SELECT pid FROM pg_catalog.pg_locks"
    " WHERE locktype = 'advisory' AND classid = %s AND objid = %s"
    " AND granted AND pid IS DISTINCT FROM pg_catalog.pg_backend_pid()"
    " ORDER BY pid"
)


def _key_halves() -> tuple[int, int]:
    key = DATAGRANT_ADVISORY_LOCK_KEY
    return (key >> 32) & 0xFFFFFFFF, key & 0xFFFFFFFF


class LockBusy(Exception):
    """The session lock was not acquired within the wait bound."""

    def __init__(self, pids: tuple[int, ...]) -> None:
        self.pids = pids
        super().__init__(lock_busy_message(pids))


def lock_busy_message(pids: tuple[int, ...]) -> str:
    who = ", ".join(str(p) for p in pids) if pids else "unknown"
    return f"another writer holds the datagrant lock (pid {who})"


def holder_pids(conn: psycopg.Connection) -> tuple[int, ...]:
    """PIDs holding our advisory key (locktype advisory), excluding this backend."""
    high, low = _key_halves()
    rows = conn.execute(_HOLDERS_SQL, (high, low)).fetchall()
    out: list[int] = []
    for row in rows:
        if row and row[0] is not None:
            out.append(int(row[0]))
    return tuple(out)


def acquire_advisory_lock(conn: psycopg.Connection) -> None:
    """Take the session lock. Blocks until the previous holder unlocks or disconnects."""
    conn.execute(_LOCK_SQL, (DATAGRANT_ADVISORY_LOCK_KEY,))


def try_advisory_lock(conn: psycopg.Connection) -> bool:
    """Non-blocking. True if this session now holds the lock."""
    row = conn.execute(_TRY_SQL, (DATAGRANT_ADVISORY_LOCK_KEY,)).fetchone()
    return bool(row and row[0])


def acquire_advisory_lock_wait(conn: psycopg.Connection, seconds: float | None = None) -> None:
    """Take the session lock, waiting up to ``seconds`` (default ``LOCK_WAIT_SECONDS``).

    Sets ``lock_timeout`` for the wait, then ``RESET lock_timeout`` so later
    work (including ``SELECT ... FOR UPDATE``) is not bound. Raises ``LockBusy``
    on timeout; no lock is held.
    """
    wait = LOCK_WAIT_SECONDS if seconds is None else seconds
    ms = max(1, int(wait * 1000))
    conn.execute("SELECT pg_catalog.set_config('lock_timeout', %s, false)", (f"{ms}ms",))
    try:
        try:
            conn.execute(_LOCK_SQL, (DATAGRANT_ADVISORY_LOCK_KEY,))
        except (LockNotAvailable, QueryCanceled) as exc:
            raise LockBusy(holder_pids(conn)) from exc
    finally:
        conn.execute("RESET lock_timeout")


def release_advisory_lock(conn: psycopg.Connection) -> None:
    """Drop the session lock. A closed session is the backstop; errors are swallowed."""
    if getattr(conn, "closed", 0):
        return
    try:
        conn.execute(_UNLOCK_SQL, (DATAGRANT_ADVISORY_LOCK_KEY,))
    except Exception:  # noqa: BLE001 - session close releases the lock
        return


@contextmanager
def session_lock(conn: psycopg.Connection, *, wait: bool) -> Iterator[bool]:
    """Acquire for the body; unlock in ``finally`` only if this session got it.

    ``wait=True``: bounded ``pg_advisory_lock`` (raises ``LockBusy``).
    ``wait=False``: ``pg_try_advisory_lock``; yields False on contention.
    """
    acquired = False
    if wait:
        acquire_advisory_lock_wait(conn)
        acquired = True
    else:
        acquired = try_advisory_lock(conn)
    try:
        yield acquired
    finally:
        if acquired:
            release_advisory_lock(conn)


@contextmanager
def holding_advisory_lock(conn: psycopg.Connection) -> Iterator[None]:
    """Unbounded ``pg_advisory_lock`` for tests and holders; unlock in ``finally``."""
    acquire_advisory_lock(conn)
    try:
        yield
    finally:
        release_advisory_lock(conn)
