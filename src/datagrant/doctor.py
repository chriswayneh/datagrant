"""Read-only ``datagrant doctor`` checks (M3).

Does not create schemas, keys, or grants, does not ``SET log_statement``,
and does not take the session advisory lock.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from datagrant.hostfs import inspect_existing, posix_mode_problem
from datagrant.keys import KeyFileError, load_hash_key, load_signing_key
from datagrant.outbox import cursor_path, read_cursor
from datagrant.pg.grant import log_statement_capability
from datagrant.policy import PolicyError, load_policy
from datagrant.receipt import ReceiptError, verify

STATUS_PASS = "pass"  # nosec B105 - check status, not a password
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_SKIP = "skip"

CHECK_KEYS = "keys"
CHECK_POLICY = "policy"
CHECK_POLICY_PERMISSIONS = "policy_permissions"
CHECK_RECEIPT_LOG_PERMISSIONS = "receipt_log_permissions"
CHECK_CONNECT = "connect"
CHECK_PREFLIGHT = "preflight"
CHECK_PG_SIGNAL_BACKEND = "pg_signal_backend"
CHECK_LOG_STATEMENT = "log_statement"
CHECK_RECEIPT_CHAIN = "receipt_chain"
CHECK_SINK_CURSOR = "sink_cursor"

CHECK_ORDER = (
    CHECK_KEYS,
    CHECK_POLICY,
    CHECK_POLICY_PERMISSIONS,
    CHECK_RECEIPT_LOG_PERMISSIONS,
    CHECK_CONNECT,
    CHECK_PREFLIGHT,
    CHECK_PG_SIGNAL_BACKEND,
    CHECK_LOG_STATEMENT,
    CHECK_RECEIPT_CHAIN,
    CHECK_SINK_CURSOR,
)

_SIGNAL_SQL = (
    "SELECT r.rolsuper OR COALESCE(("
    " SELECT pg_catalog.pg_has_role(r.oid, g.oid, 'USAGE')"
    " FROM pg_catalog.pg_roles g WHERE g.rolname = 'pg_signal_backend'"
    "), false)"
    " FROM pg_catalog.pg_roles r WHERE r.rolname = current_user"
)
_PARAM_SQL = (
    "SELECT pg_catalog.has_parameter_privilege(current_user, 'log_statement', 'SET')"
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


def _file_check(
    add: Callable[[str, str, str], None],
    name: str,
    path: Path,
    what: str,
    *,
    fail_on_access: bool,
) -> None:
    result = inspect_existing(path, what)
    msgs: list[str] = []
    access: str | None = None
    if isinstance(result, str):
        access = result
        msgs.append(result)
    elif result is not None:
        access = result.access_message()
        if access:
            msgs.append(access)
        msgs.extend(result.extra_warnings())
    if not msgs:
        add(name, STATUS_PASS, str(path))
        return
    detail = "; ".join(msgs)
    if access and fail_on_access:
        add(name, STATUS_FAIL, detail)
    else:
        add(name, STATUS_WARN, detail)


def _bool_row(row: Any) -> bool:
    if not row:
        return False
    v = row[0]
    if isinstance(v, str):
        return v.lower() in {"t", "true", "on", "1"}
    return bool(v)


def run_doctor(
    *,
    signing_path: Path,
    hash_path: Path,
    policy_path: Path | None,
    receipt_log: Path,
    dsn: str | None,
    sink_configured: bool,
    connect: Callable[[], Any] | None = None,
    scrub: Callable[[str], str] = lambda s: s,
    force_strict_policy_permissions: bool = False,
) -> list[Check]:
    """Run checks in design order. ``connect`` is injected in tests."""
    out: list[Check] = []

    def add(name: str, status: str, detail: str = "") -> None:
        out.append(Check(name, status, scrub(detail)))

    signing = None
    key_errs: list[str] = []
    try:
        signing = load_signing_key(signing_path)
    except KeyFileError as exc:
        key_errs.append(str(exc))
    try:
        load_hash_key(hash_path)
    except KeyFileError as exc:
        key_errs.append(str(exc))
    if key_errs:
        add(CHECK_KEYS, STATUS_FAIL, "; ".join(key_errs))
    else:
        add(CHECK_KEYS, STATUS_PASS, f"signing {signing_path}, hash {hash_path}")

    if policy_path is None:
        add(CHECK_POLICY, STATUS_FAIL, "no policy: pass --policy or set $DATAGRANT_POLICY")
        add(CHECK_POLICY_PERMISSIONS, STATUS_SKIP, "no policy path")
    else:
        inspected = inspect_existing(policy_path, "policy file")
        access: str | None = None
        extras: list[str] = []
        if isinstance(inspected, str):
            access = inspected
        elif inspected is not None:
            access = inspected.access_message()
            extras = inspected.extra_warnings()
        if access and force_strict_policy_permissions:
            add(
                CHECK_POLICY,
                STATUS_SKIP,
                "not parsed: policy file is group/other-accessible",
            )
            add(CHECK_POLICY_PERMISSIONS, STATUS_FAIL, "; ".join([access, *extras]))
        else:
            pol = None
            try:
                pol = load_policy(policy_path)
                add(CHECK_POLICY, STATUS_PASS, f"sha256={pol.sha256}")
            except (PolicyError, OSError) as exc:
                msg = (
                    str(exc)
                    if not isinstance(exc, OSError)
                    else f"{exc.strerror}: {exc.filename}"
                )
                add(CHECK_POLICY, STATUS_FAIL, msg)
            fail = bool(pol and pol.strict_policy_permissions) or force_strict_policy_permissions
            _file_check(
                add,
                CHECK_POLICY_PERMISSIONS,
                policy_path,
                "policy file",
                fail_on_access=fail,
            )

    log_probs = [
        p
        for p in (
            posix_mode_problem(receipt_log, "receipt log"),
            posix_mode_problem(cursor_path(receipt_log), "sink cursor"),
        )
        if p
    ]
    log_extras: list[str] = []
    for pth, label in (
        (receipt_log, "receipt log"),
        (cursor_path(receipt_log), "sink cursor"),
    ):
        inspected = inspect_existing(pth, label)
        if inspected is not None and not isinstance(inspected, str):
            log_extras.extend(inspected.extra_warnings())
    if log_probs:
        add(CHECK_RECEIPT_LOG_PERMISSIONS, STATUS_FAIL, "; ".join(log_probs + log_extras))
    elif log_extras:
        add(CHECK_RECEIPT_LOG_PERMISSIONS, STATUS_WARN, "; ".join(log_extras))
    elif not receipt_log.exists() and not cursor_path(receipt_log).exists():
        add(CHECK_RECEIPT_LOG_PERMISSIONS, STATUS_PASS, "no receipt log or cursor yet")
    else:
        add(CHECK_RECEIPT_LOG_PERMISSIONS, STATUS_PASS, str(receipt_log))

    conn: Any = None
    if not dsn and connect is None:
        add(CHECK_CONNECT, STATUS_FAIL, "no database: pass --dsn or set $DATAGRANT_DSN")
        add(CHECK_PREFLIGHT, STATUS_SKIP, "not connected")
        add(CHECK_PG_SIGNAL_BACKEND, STATUS_SKIP, "not connected")
        add(CHECK_LOG_STATEMENT, STATUS_SKIP, "not connected")
    else:
        try:
            opener = connect if connect is not None else _default_connect(dsn or "")
            raw = opener()
        except Exception as exc:  # noqa: BLE001 - connection errors become a failed check
            add(CHECK_CONNECT, STATUS_FAIL, f"cannot connect: {exc}")
            add(CHECK_PREFLIGHT, STATUS_SKIP, "not connected")
            add(CHECK_PG_SIGNAL_BACKEND, STATUS_SKIP, "not connected")
            add(CHECK_LOG_STATEMENT, STATUS_SKIP, "not connected")
        else:
            entered = False
            try:
                conn = raw.__enter__() if hasattr(raw, "__enter__") else raw
                entered = hasattr(raw, "__enter__")
                add(CHECK_CONNECT, STATUS_PASS, "connected")
                _preflight_check(conn, add)
                _signal_check(conn, add)
                _log_statement_check(conn, add)
            except Exception as exc:  # noqa: BLE001 - remaining DB checks fail closed
                if not any(c.name == CHECK_CONNECT for c in out):
                    add(CHECK_CONNECT, STATUS_FAIL, str(exc))
                _skip_remaining_db(out, add, str(exc))
            finally:
                if entered:
                    raw.__exit__(None, None, None)
                elif conn is not None and hasattr(conn, "close"):
                    with suppress(Exception):
                        conn.close()

    if signing is None:
        add(CHECK_RECEIPT_CHAIN, STATUS_SKIP, "signing key unavailable")
    elif not receipt_log.exists() and not receipt_log.is_symlink():
        add(CHECK_RECEIPT_CHAIN, STATUS_PASS, "0 receipts (no log yet)")
    else:
        res = verify(receipt_log, signing.private.public_key())
        if res.ok:
            add(CHECK_RECEIPT_CHAIN, STATUS_PASS, f"{res.count} receipt(s), head {res.head_sha256}")
        else:
            add(CHECK_RECEIPT_CHAIN, STATUS_FAIL, res.error or "chain failed")

    if not sink_configured:
        add(CHECK_SINK_CURSOR, STATUS_SKIP, "no sink configured")
    else:
        try:
            acked = read_cursor(receipt_log)
        except ReceiptError as exc:
            add(CHECK_SINK_CURSOR, STATUS_FAIL, str(exc))
        else:
            if acked < 0:
                add(CHECK_SINK_CURSOR, STATUS_PASS, "no cursor yet")
            else:
                add(CHECK_SINK_CURSOR, STATUS_PASS, f"acked_seq {acked}")

    return out


def _default_connect(dsn: str) -> Callable[[], Any]:
    def open_conn() -> Any:
        import psycopg

        return psycopg.connect(dsn, autocommit=True)

    return open_conn


def _skip_remaining_db(
    out: Sequence[Check], add: Callable[[str, str, str], None], detail: str
) -> None:
    have = {c.name for c in out}
    for name in (CHECK_PREFLIGHT, CHECK_PG_SIGNAL_BACKEND, CHECK_LOG_STATEMENT):
        if name not in have:
            add(name, STATUS_SKIP, detail)


def _preflight_check(conn: Any, add: Callable[[str, str, str], None]) -> None:
    from datagrant.pg.grant import preflight

    warnings = preflight(conn)
    if warnings:
        add(CHECK_PREFLIGHT, STATUS_WARN, "; ".join(warnings))
    else:
        add(CHECK_PREFLIGHT, STATUS_PASS, "no PUBLIC warnings")


def _signal_check(conn: Any, add: Callable[[str, str, str], None]) -> None:
    try:
        row = conn.execute(_SIGNAL_SQL).fetchone()
    except Exception as exc:  # noqa: BLE001 - privilege probe
        add(CHECK_PG_SIGNAL_BACKEND, STATUS_FAIL, str(exc))
        return
    if _bool_row(row):
        add(CHECK_PG_SIGNAL_BACKEND, STATUS_PASS, "superuser or pg_signal_backend")
    else:
        add(
            CHECK_PG_SIGNAL_BACKEND,
            STATUS_FAIL,
            "admin is not superuser and is not a member of pg_signal_backend",
        )


def _log_statement_check(conn: Any, add: Callable[[str, str, str], None]) -> None:
    ok, detail = log_statement_capability(conn)
    add(CHECK_LOG_STATEMENT, STATUS_PASS if ok else STATUS_FAIL, detail)
