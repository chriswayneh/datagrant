"""datagrant command line (unit U6).

Exit codes: 0 ok, 1 denied/failed, 2 usage, 3 receipt could not be written
(access change still happened), 4 revoke failed (grant still active; retried
by the next sweep).

Every command that changes something (keys init, request, approve, revoke,
sweep, preflight) is a dry run unless ``--apply`` is given: it prints what
would change and changes nothing. A dry run never generates or prints a
password or verifier. ``--dry-run`` is accepted as a no-op alias.

Identity is the OS user (getpass.getuser()). ``--as-user`` overrides it for
automation and tests. Neither is authentication: anyone who can run datagrant
with the admin DSN can claim any name. Real separation of duties needs the
admin DSN held by a trusted service.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from datagrant import __version__, receipt
from datagrant.keys import (
    KeyFileError,
    init_keys,
    load_hash_key,
    load_public_key,
    load_signing_key,
    resolve_key_path,
)

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_RECEIPT, EXIT_REVOKE_FAILED = 0, 1, 2, 3, 4
DSN_ENV = "DATAGRANT_DSN"
REDACTED = "<redacted>"
POLICY_ENV = "DATAGRANT_POLICY"


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code


_PW_KV = re.compile(r"(password\s*=\s*)('(?:[^'\\]|\\.)*'|\S+)", re.IGNORECASE)
_PW_URL = re.compile(r"(\w+://[^:/@\s]*:)[^@\s]*@")


def redact(text: str, dsn: str | None = None) -> str:
    """Remove passwords from DSNs/conninfo strings and any literal DSN password."""
    if dsn:
        try:
            import psycopg

            pw = psycopg.conninfo.conninfo_to_dict(dsn).get("password")
        except Exception:  # noqa: BLE001 - malformed DSN: fall back to patterns
            pw = None
        if isinstance(pw, str) and pw:
            text = text.replace(pw, "***")
    return _PW_URL.sub(r"\1***@", _PW_KV.sub(r"\1***", text))


@dataclass
class Ctx:
    args: argparse.Namespace
    out: Callable[[str], None]

    @property
    def json(self) -> bool:
        return bool(self.args.json)

    def emit(self, data: dict[str, Any], text: str) -> None:
        self.out(json.dumps(data, sort_keys=True, default=str) if self.json else text)


def _identity(args: argparse.Namespace) -> tuple[str, str]:
    if getattr(args, "as_user", None):
        return args.as_user, "flag"
    return getpass.getuser(), "os"


def _dsn(args: argparse.Namespace) -> str:
    dsn = args.dsn or os.environ.get(DSN_ENV)
    if not dsn:
        raise CliError(f"no database: pass --dsn or set ${DSN_ENV}", EXIT_USAGE)
    return dsn


def _connect(args: argparse.Namespace) -> Any:
    import psycopg

    dsn = _dsn(args)
    try:
        return psycopg.connect(dsn, autocommit=True)
    except psycopg.Error as exc:
        raise CliError(f"cannot connect: {redact(str(exc), dsn).strip()}") from None


def _policy(args: argparse.Namespace) -> Any:
    from datagrant.policy import load_policy

    path = args.policy or os.environ.get(POLICY_ENV)
    if not path:
        raise CliError(f"no policy: pass --policy or set ${POLICY_ENV}", EXIT_USAGE)
    return load_policy(path)


def _sink(args: argparse.Namespace) -> Any:
    from datagrant.pg.grant import ReceiptSink

    key = load_signing_key(resolve_key_path("signing", args.signing_key))
    log = Path(args.receipt_log) if args.receipt_log else receipt.default_log_path()
    return ReceiptSink(log, key)


def _remote(args: argparse.Namespace) -> Any:
    """The external sink config (validated in main), or None."""
    return getattr(args, "_remote", None)


def _log_path(args: argparse.Namespace) -> Path:
    return Path(args.receipt_log) if args.receipt_log else receipt.default_log_path()


def _hide_token(text: str) -> str:
    from datagrant.sink import SINK_TOKEN_ENV

    tok = os.environ.get(SINK_TOKEN_ENV)
    return text.replace(tok, "***") if tok else text


def _warn(ctx: Ctx, msg: str) -> None:
    print(f"datagrant: warning: {_hide_token(msg)}", file=sys.stderr)


def _check_outbox(ctx: Ctx, local: Any) -> None:
    """Before issuing: the outbox must be sound (cursor private, no symlink, not ahead)."""
    from datagrant.outbox import pending_lines
    from datagrant.receipt import ReceiptError

    if _remote(ctx.args) is None:
        return
    try:
        pending_lines(local.log)
    except ReceiptError as exc:
        raise CliError(f"receipt outbox unusable, not issuing: {exc}", EXIT_RECEIPT) from None


def _deliver_issued(ctx: Ctx, conn: Any, plan: Any, local: Any) -> None:
    """After an issued receipt: flush the outbox. Required mode: no delivery, no access."""
    from datagrant.outbox import flush

    remote = _remote(ctx.args)
    if remote is None:
        return
    res = flush(local.log, remote.sink)
    if res.error is None:
        return
    if remote.mode != "required":
        _warn(ctx, f"receipt not delivered to sink, {res.pending} pending: {res.error}")
        return
    from datagrant.outbox import quick
    from datagrant.pg.revoke import revoke

    r = revoke(conn, plan.grant_id, "manual", local)
    flush(local.log, quick(remote.sink))  # best effort for the revoked receipt
    state = (
        "grant revoked"
        if r.outcome == "revoked"
        else f"revoke {r.outcome} ({r.error}): grant STILL ACTIVE until the next sweep"
    )
    raise CliError(
        _hide_token(f"grant {plan.grant_id}: receipt not delivered to sink ({res.error}); {state}"),
        EXIT_RECEIPT,
    )


def _deliver_quick(ctx: Ctx, local: Any) -> dict[str, Any] | None:
    """After revoke/sweep: one attempt, no retries. Never changes the exit code."""
    from datagrant.outbox import flush, quick

    remote = _remote(ctx.args)
    if remote is None or local is None:
        return None
    res = flush(local.log, quick(remote.sink))
    if res.error is not None:
        _warn(ctx, f"receipts not delivered to sink, {res.pending} pending: {res.error}")
    d = res.as_dict()
    d["error"] = _hide_token(res.error) if res.error else None
    return d


def _conn_info(args: argparse.Namespace, plan: Any) -> dict[str, Any]:
    import psycopg

    info = psycopg.conninfo.conninfo_to_dict(_dsn(args))
    return {
        "host": info.get("host") or "localhost",
        "port": int(info.get("port") or 5432),
        "dbname": plan.database,
        "user": plan.role,
    }


# ---- commands -------------------------------------------------------------


def cmd_keys_init(ctx: Ctx) -> int:
    a = ctx.args
    hp0 = resolve_key_path("hash", a.hash_key, a.dir)
    sp0 = resolve_key_path("signing", a.signing_key, a.dir)
    if hp0.absolute() == sp0.absolute() or (hp0.exists() and sp0.exists() and hp0.samefile(sp0)):
        raise CliError(f"hash key and signing key resolve to the same file {sp0}", EXIT_USAGE)
    if not ctx.args.apply:
        a = ctx.args
        hp = resolve_key_path("hash", a.hash_key, a.dir)
        sp = resolve_key_path("signing", a.signing_key, a.dir)
        exists = [str(x) for x in (hp, sp) if x.exists() or x.is_symlink()]
        ctx.emit(
            {"dry_run": True, "would_create": [str(hp), str(sp)], "already_exist": exists},
            f"dry run: would create {hp} and {sp} (0600)"
            + (f"\nrefused with --apply: already exist: {', '.join(exists)}" if exists else "")
            + "\nre-run with --apply to create them",
        )
        return EXIT_FAILED if exists else EXIT_OK
    a = ctx.args
    hp, sp, pub = init_keys(a.dir, hash_path=a.hash_key, signing_path=a.signing_key)
    ctx.emit(
        {"hash_key": str(hp), "signing_key": str(sp), "public_key": pub},
        f"created {hp}\ncreated {sp}\npublic key: {pub}\nBack up both files (see runbook).",
    )
    return EXIT_OK


def cmd_keys_export(ctx: Ctx) -> int:
    a = ctx.args
    key = load_signing_key(resolve_key_path("signing", a.signing_key))
    ctx.emit({"public_key": key.public_hex(), "key_id": key.key_id}, key.public_hex())
    return EXIT_OK


def cmd_policy_check(ctx: Ctx) -> int:
    from datagrant.policy import load_policy

    p = load_policy(ctx.args.file)
    tables = sum(len(d.tables) for d in p.datasets.values())
    ctx.emit(
        {
            "ok": True,
            "sha256": p.sha256,
            "approval": p.approval,
            "datasets": sorted(p.datasets),
            "tables": tables,
        },
        f"policy OK: {len(p.datasets)} dataset(s), {tables} table(s), approval={p.approval},"
        f" sha256={p.sha256}",
    )
    return EXIT_OK


def _redacted_sql(plan: Any) -> list[str]:
    out = []
    for s in plan.statements:
        text = s.as_string(None)
        out.append(re.sub(r"PASSWORD '[^']*'", "PASSWORD '<redacted>'", text))
    return out


def _needs_hash(decision: Any, cols: Sequence[str]) -> bool:
    return any(decision.masks.get(c) == "hash" for c in cols)


def cmd_request(ctx: Ctx) -> int:
    from datagrant.pg.grant import build_plan, ensure_state, new_password
    from datagrant.pg.mask import inspect_table
    from datagrant.pg.requests import create_request
    from datagrant.pg.scram import scram_verifier
    from datagrant.policy import Request, evaluate, parse_duration

    a = ctx.args
    policy = _policy(a)
    user, source = _identity(a)
    cols = tuple(c.strip() for c in a.columns.split(",") if c.strip())
    req = Request(
        user,
        a.dataset,
        a.table,
        cols,
        parse_duration(a.duration, "--duration"),
        a.purpose,
        a.row_filter,
    )
    decision = evaluate(policy, req)
    if not decision.allowed:
        ctx.emit(
            {"allowed": False, "reasons": list(decision.reasons), "requester": user},
            "denied:\n" + "\n".join(f"  - {r}" for r in decision.reasons),
        )
        return EXIT_FAILED
    two_person = decision.approval == "two-person"
    hash_key = (
        load_hash_key(resolve_key_path("hash", a.hash_key)) if _needs_hash(decision, cols) else None
    )
    with _connect(a) as conn:
        catalog = inspect_table(conn, req.table)
        if not a.apply:
            # No password is generated in a dry run; the verifier slot is a placeholder.
            plan = build_plan(
                decision,
                req,
                database=policy.datasets[req.dataset].database,
                password="",  # nosec B106 - dry run: no password exists
                verifier=REDACTED,
                catalog=catalog,
                hash_key=hash_key,
                approvers=("<approver>",) if two_person else (),
            )
            sqls = _redacted_sql(plan)
            what = (
                "store a pending request for another person to approve; on approval run"
                if two_person
                else "run"
            )
            ctx.emit(
                {"dry_run": True, "approval": decision.approval, "sql": sqls},
                f"dry run: allowed by policy; with --apply datagrant would {what}:\n"
                + "\n".join(x + ";" for x in sqls),
            )
            return EXIT_OK
        sink = _sink(a)  # no signing key, no grant
        _check_outbox(ctx, sink)
        ensure_state(conn)
        password = new_password()
        if two_person:
            pending = create_request(
                conn,
                req,
                policy_sha256=policy.sha256,
                verifier=scram_verifier(password),
                ttl=parse_duration(a.pending_ttl, "--pending-ttl"),
            )
            ctx.emit(
                {
                    "status": "pending",
                    "request_id": pending.id,
                    "requester": user,
                    "identity_source": source,
                    "pending_expires_at": pending.expires_at,
                    "password": password,
                },
                f"request {pending.id} is pending approval by another person"
                f" (expires {pending.expires_at.isoformat()}).\n"
                f"one-time password (shown once, works after approval): {password}",
            )
            return EXIT_OK
        plan = build_plan(
            decision,
            req,
            database=policy.datasets[req.dataset].database,
            password=password,
            catalog=catalog,
            hash_key=hash_key,
        )
        from datagrant.pg.grant import apply_plan

        apply_plan(conn, plan, sink)
        _deliver_issued(ctx, conn, plan, sink)
    return _print_grant(ctx, plan, password, user, source)


def _print_grant(ctx: Ctx, plan: Any, password: str | None, user: str, source: str) -> int:
    info = _conn_info(ctx.args, plan)
    data = {
        "status": "granted",
        "grant_id": plan.grant_id,
        "view": plan.view,
        "expires_at": plan.expires_at,
        "requester": user,
        "identity_source": source,
        "connection": info,
    }
    text = (
        f"grant {plan.grant_id} active until {plan.expires_at.isoformat()}\n"
        f"connect: host={info['host']} port={info['port']} dbname={info['dbname']}"
        f" user={info['user']}\nquery:   SELECT * FROM {plan.view};"  # nosec B608 - display text
    )
    if password is not None:
        data["password"] = password
        text += f"\none-time password (shown once, not stored): {password}"
    ctx.emit(data, text)
    return EXIT_OK


def cmd_approve(ctx: Ctx) -> int:
    from datagrant.pg.grant import apply_plan, build_plan, ensure_state, new_password
    from datagrant.pg.mask import inspect_table
    from datagrant.pg.requests import get_request
    from datagrant.policy import evaluate

    a = ctx.args
    policy = _policy(a)
    approver, source = _identity(a)
    with _connect(a) as conn:
        if a.apply:
            ensure_state(conn)
        pending = get_request(conn, a.request_id)
        if pending.status != "pending" or pending.verifier is None:
            raise CliError(f"request {pending.id} is {pending.status}, not pending")
        reasons = policy.can_approve(approver, pending.request.requester)
        decision = evaluate(policy, pending.request)  # re-check against the current policy
        if not decision.allowed:
            reasons += [f"request no longer allowed: {r}" for r in decision.reasons]
        if reasons:
            ctx.emit(
                {"approved": False, "reasons": reasons},
                "not approved:\n" + "\n".join(f"  - {r}" for r in reasons),
            )
            return EXIT_FAILED
        cols = pending.request.columns
        hash_key = (
            load_hash_key(resolve_key_path("hash", a.hash_key))
            if _needs_hash(decision, cols)
            else None
        )
        if not a.apply:
            plan = build_plan(
                decision,
                pending.request,
                database=policy.datasets[pending.request.dataset].database,
                password="",  # nosec B106 - dry run: no password exists
                verifier=REDACTED,
                catalog=inspect_table(conn, pending.request.table),
                hash_key=hash_key,
                approvers=(approver,),
            )
            sqls = _redacted_sql(plan)
            ctx.emit(
                {"dry_run": True, "request_id": pending.id, "approver": approver, "sql": sqls},
                f"dry run: {approver} may approve request {pending.id}; with --apply:\n"
                + "\n".join(x + ";" for x in sqls),
            )
            return EXIT_OK
        sink = _sink(a)
        _check_outbox(ctx, sink)
        plan = build_plan(
            decision,
            pending.request,
            database=policy.datasets[pending.request.dataset].database,
            password=new_password(),
            verifier=pending.verifier,
            catalog=inspect_table(conn, pending.request.table),
            hash_key=hash_key,
            approvers=(approver,),
        )
        apply_plan(conn, plan, sink, request_id=pending.id, approver=approver)
        _deliver_issued(ctx, conn, plan, sink)
    _print_grant(ctx, plan, None, pending.request.requester, source)
    return EXIT_OK


_GRANT_COLS = (
    "id",
    "requester",
    "dataset",
    "table_name",
    "columns",
    "row_filter",
    "status",
    "created_at",
    "expires_at",
    "revoked_at",
    "revoke_reason",
    "approvers",
    "last_error",
)


def _grant_rows(conn: Any, where: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    from psycopg import sql

    q = sql.SQL("SELECT {} FROM datagrant.grants {} ORDER BY created_at, id").format(
        sql.SQL(", ").join(sql.Identifier(c) for c in _GRANT_COLS),
        sql.SQL(where),
    )
    return [dict(zip(_GRANT_COLS, r, strict=True)) for r in conn.execute(q, params).fetchall()]


def cmd_grant_list(ctx: Ctx) -> int:

    with _connect(ctx.args) as conn:
        rows = _grant_rows(conn, "" if ctx.args.all else "WHERE status = 'active'", ())
    text = (
        "\n".join(
            f"{r['id']}  {r['status']:<8} {r['requester']:<12} {r['dataset']}/{r['table_name']}"
            f"  expires {r['expires_at']:%Y-%m-%d %H:%M %Z}"
            + (f"  ERROR: {r['last_error']}" if r["last_error"] else "")
            for r in rows
        )
        or "no grants"
    )
    ctx.emit({"grants": rows}, text)
    return EXIT_OK


def cmd_grant_status(ctx: Ctx) -> int:

    with _connect(ctx.args) as conn:
        rows = _grant_rows(conn, "WHERE id = %s", (ctx.args.grant_id,))
    if not rows:
        raise CliError(f"unknown grant {ctx.args.grant_id}")
    r = rows[0]
    ctx.emit(r, "\n".join(f"{k}: {'-' if v is None else v}" for k, v in r.items()))
    return EXIT_OK


def _revoke_receipts(ctx: Ctx) -> tuple[Any, str | None]:
    try:
        return _sink(ctx.args), None
    except KeyFileError as exc:
        return None, str(exc)  # still revoke: removing access never waits on a key


def _result_dict(r: Any) -> dict[str, Any]:
    return {
        "grant_id": r.grant_id,
        "outcome": r.outcome,
        "sessions_terminated": r.sessions_terminated,
        "error": r.error,
        "receipt_error": r.receipt_error,
    }


def _exit_for(results: Sequence[Any], key_problem: str | None) -> int:
    if any(r.outcome == "failed" for r in results):
        return EXIT_REVOKE_FAILED
    if any(r.receipt_error for r in results) or (key_problem and results):
        return EXIT_RECEIPT
    return EXIT_OK


def cmd_revoke(ctx: Ctx) -> int:
    from datagrant.pg.grant import ensure_state
    from datagrant.pg.revoke import revoke

    if not ctx.args.apply:
        with _connect(ctx.args) as conn:
            rows = _grant_rows(conn, "WHERE id = %s", (ctx.args.grant_id,))
            if not rows:
                raise CliError(f"unknown grant {ctx.args.grant_id}")
            role = f"dg_{ctx.args.grant_id}"
            n = conn.execute(
                "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename = %s", (role,)
            ).fetchone()[0]
        active = rows[0]["status"] == "active"
        ctx.emit(
            {
                "dry_run": True,
                "grant_id": ctx.args.grant_id,
                "status": rows[0]["status"],
                "would_revoke": active,
                "open_sessions": n,
            },
            f"dry run: grant {ctx.args.grant_id} is {rows[0]['status']}; "
            + (
                f"--apply would lock out {role}, end {n} session(s), drop its view and role"
                if active
                else "nothing to do"
            ),
        )
        return EXIT_OK
    sink, key_problem = _revoke_receipts(ctx)
    with _connect(ctx.args) as conn:
        ensure_state(conn)
        r = revoke(conn, ctx.args.grant_id, "manual", sink)
    delivery = _deliver_quick(ctx, sink)
    code = _exit_for([r] if r.outcome != "noop" else [], key_problem)
    msg = f"grant {r.grant_id}: {r.outcome}"
    if r.outcome == "revoked":
        msg += f" ({r.sessions_terminated} session(s) ended)"
    if r.error:
        msg += f"\nerror: {r.error}"
    if r.receipt_error or (key_problem and r.outcome != "noop"):
        msg += f"\nreceipt not written: {r.receipt_error or key_problem}"
    ctx.emit(_result_dict(r) | {"key_problem": key_problem, "sink": delivery}, msg)
    return code


def cmd_sweep(ctx: Ctx) -> int:
    from datagrant.pg.grant import ensure_state
    from datagrant.pg.requests import expire_requests
    from datagrant.pg.revoke import sweep

    if not ctx.args.apply:
        with _connect(ctx.args) as conn:
            due = [
                r["id"]
                for r in _grant_rows(
                    conn, "WHERE status = 'active' AND expires_at <= pg_catalog.now()", ()
                )
            ]
            stale = [
                r[0]
                for r in conn.execute(
                    "SELECT id FROM datagrant.requests WHERE status = 'pending'"
                    " AND expires_at <= pg_catalog.now() ORDER BY id"
                ).fetchall()
            ]
        ctx.emit(
            {"dry_run": True, "would_revoke": due, "would_expire_requests": stale},
            "dry run: --apply would "
            + (f"revoke expired grants {', '.join(due)}" if due else "revoke no grants")
            + (f" and expire requests {', '.join(stale)}" if stale else ""),
        )
        return EXIT_OK
    sink, key_problem = _revoke_receipts(ctx)
    with _connect(ctx.args) as conn:
        ensure_state(conn)
        results = sweep(conn, sink)
        expired_requests = expire_requests(conn)
    delivery = _deliver_quick(ctx, sink)
    lines = [
        f"grant {r.grant_id}: {r.outcome}"
        + (f" ({r.error})" if r.error else "")
        + (f" [receipt not written: {r.receipt_error}]" if r.receipt_error else "")
        for r in results
    ]
    lines += [f"request {rid}: expired" for rid in expired_requests]
    if key_problem and results:
        lines.append(f"receipts not written: {key_problem}")
    ctx.emit(
        {
            "results": [_result_dict(r) for r in results],
            "expired_requests": expired_requests,
            "key_problem": key_problem,
            "sink": delivery,
        },
        "\n".join(lines) or "nothing to sweep",
    )
    return _exit_for(results, key_problem)


def cmd_receipts_verify(ctx: Ctx) -> int:
    a = ctx.args
    if a.pubkey:
        text = Path(a.pubkey).read_text() if Path(a.pubkey).is_file() else a.pubkey
        pub = load_public_key(text)
    else:
        key = load_signing_key(resolve_key_path("signing", a.signing_key))
        pub = key.private.public_key()
    log = Path(a.receipt_log) if a.receipt_log else receipt.default_log_path()
    res = receipt.verify(log, pub, expect_head=a.expect_head)
    data: dict[str, Any] = {
        "ok": res.ok,
        "count": res.count,
        "head_sha256": res.head_sha256,
        "error": res.error,
        "line": res.line,
    }
    text = (
        f"OK: {res.count} receipt(s), head {res.head_sha256}"
        if res.ok
        else "FAILED"
        + (f" at line {res.line}" if res.line is not None else "")
        + f": {res.error} ({res.count} good receipt(s) before it)"
    )
    remote = _remote(a)
    if remote is not None and res.ok:
        from datagrant.outbox import compare_with_sink

        chk = compare_with_sink(log, remote.sink, res.count)  # read-only: no cursor or sink writes
        data |= chk.as_dict()
        if not chk.ok:
            err = _hide_token(chk.error or "sink check failed")
            data |= {"ok": False, "error": err}
            text += f"\nSINK FAILED: {err}"
        elif chk.sink_seq is None:
            text += f"\nsink is empty; {chk.undelivered} receipt(s) not yet delivered"
        else:
            text += f"\nsink OK: head seq {chk.sink_seq} matches"
            if chk.undelivered:
                text += f"; {chk.undelivered} receipt(s) not yet delivered"
        ctx.emit(data, text)
        return EXIT_OK if chk.ok else EXIT_FAILED
    ctx.emit(data, text)
    return EXIT_OK if res.ok else EXIT_FAILED


def cmd_receipts_push(ctx: Ctx) -> int:
    from datagrant.outbox import flush, pending_lines

    remote = _remote(ctx.args)
    if remote is None:
        raise CliError(
            "no receipt sink: pass --receipt-sink or set $DATAGRANT_RECEIPT_SINK", EXIT_USAGE
        )
    log = _log_path(ctx.args)
    if not ctx.args.apply:
        n = len(pending_lines(log))
        ctx.emit(
            {"dry_run": True, "pending": n, "sink": remote.sink.name},
            f"dry run: {n} receipt(s) pending; --apply would send them to {remote.sink.name}",
        )
        return EXIT_OK
    res = flush(log, remote.sink)
    err = _hide_token(res.error) if res.error else None
    ctx.emit(
        {"delivered": res.delivered, "pending": res.pending, "error": err},
        f"delivered {res.delivered} receipt(s), {res.pending} pending"
        + (f": {err}" if err else ""),
    )
    return EXIT_RECEIPT if res.error else EXIT_OK


def cmd_preflight(ctx: Ctx) -> int:
    from datagrant.pg.grant import ensure_state, preflight

    with _connect(ctx.args) as conn:
        warnings = ensure_state(conn) if ctx.args.apply else preflight(conn)
    if not ctx.args.apply:
        warnings = [*warnings, "dry run: state schemas not created/updated; use --apply"]
    ctx.emit(
        {"warnings": warnings},
        "\n".join(f"WARNING: {w}" for w in warnings) or "preflight OK: no warnings",
    )
    return EXIT_OK


# ---- parser ---------------------------------------------------------------


_SINK = ("receipt_sink", "receipt_sink_mode")
_GRANTING = ("json", "dsn", "signing_key", "hash_key", "receipt_log", *_SINK)
_REVOKING = ("json", "dsn", "signing_key", "receipt_log", *_SINK)


def build_parser() -> argparse.ArgumentParser:
    # Each option lives in its own parent so a subcommand only advertises what it uses.
    # Subcommand copies use SUPPRESS so a value given before the subcommand is kept.
    sup: dict[str, Any] = {"default": argparse.SUPPRESS}
    opts: dict[str, tuple[tuple[str, ...], dict[str, Any]]] = {
        "json": (("--json",), {"action": "store_true", "help": "machine-readable output"}),
        "dsn": (("--dsn",), {"help": f"admin connection string (default ${DSN_ENV})"}),
        "signing_key": (
            ("--signing-key",),
            {"help": "signing key file (beats $DATAGRANT_SIGNING_KEY, then ~/.config/datagrant)"},
        ),
        "hash_key": (
            ("--hash-key",),
            {"help": "hash key file (beats $DATAGRANT_HASH_KEY, then ~/.config/datagrant)"},
        ),
        "receipt_log": (
            ("--receipt-log",),
            {"help": "receipt log (default $DATAGRANT_RECEIPT_LOG)"},
        ),
        "receipt_sink": (
            ("--receipt-sink",),
            {
                "help": "external receipt sink, https:// or file:/// URL"
                " (default $DATAGRANT_RECEIPT_SINK; token only via $DATAGRANT_RECEIPT_SINK_TOKEN)"
            },
        ),
        "receipt_sink_mode": (
            ("--receipt-sink-mode",),
            {
                "choices": ("required", "best-effort"),
                "help": "required: a grant whose receipt can't reach the sink is revoked"
                " (default $DATAGRANT_RECEIPT_SINK_MODE, else best-effort)",
            },
        ),
    }

    # keys init is the only command with --dir, so only its key help mentions it.
    with_dir: dict[str, tuple[tuple[str, ...], dict[str, Any]]] = {
        "signing_key": (
            ("--signing-key",),
            {
                "help": "signing key file (beats $DATAGRANT_SIGNING_KEY, then --dir, "
                "then ~/.config/datagrant)"
            },
        ),
        "hash_key": (
            ("--hash-key",),
            {
                "help": "hash key file (beats $DATAGRANT_HASH_KEY, then --dir, "
                "then ~/.config/datagrant)"
            },
        ),
    }

    def only(*names: str, dir_help: bool = False) -> list[argparse.ArgumentParser]:
        out = []
        for n in names:
            c = argparse.ArgumentParser(add_help=False)
            flags, kw = with_dir[n] if dir_help and n in with_dir else opts[n]
            c.add_argument(*flags, **kw, **sup)
            out.append(c)
        return out

    ident = argparse.ArgumentParser(add_help=False)
    ident.add_argument(
        "--as-user",
        help="act as this name instead of the OS user. NOT authentication: for automation/tests",
    )
    apply = argparse.ArgumentParser(add_help=False)
    apply.add_argument(
        "--apply", action="store_true", help="make the change (default is a dry run)"
    )
    apply.add_argument(
        "--dry-run", action="store_true", help="no-op: dry run is already the default"
    )
    pol = argparse.ArgumentParser(add_help=False)
    pol.add_argument("--policy", help=f"policy YAML (default ${POLICY_ENV})")

    p = argparse.ArgumentParser(
        prog="datagrant",
        description="Just-in-time, expiring, masked access to regulated data, with receipts.",
    )
    for flags, kw in opts.values():
        p.add_argument(*flags, **kw)
    p.add_argument("--version", action="version", version=f"datagrant {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    keys = sub.add_parser("keys", help="create or export keys").add_subparsers(
        dest="sub", required=True
    )
    k = keys.add_parser(
        "init",
        parents=[*only("json", "signing_key", "hash_key", dir_help=True), apply],
        help="create hash + signing keys (0600)",
    )
    k.add_argument(
        "--dir",
        help="directory for both keys; --signing-key/--hash-key and the env vars win over it",
    )
    k.set_defaults(fn=cmd_keys_init)
    keys.add_parser(
        "export-pubkey", parents=only("json", "signing_key"), help="print the receipt public key"
    ).set_defaults(fn=cmd_keys_export)

    pc = sub.add_parser("policy", help="policy tools").add_subparsers(dest="sub", required=True)
    c = pc.add_parser("check", parents=only("json"), help="validate a policy file")
    c.add_argument("file")
    c.set_defaults(fn=cmd_policy_check)

    r = sub.add_parser(
        "request", parents=[*only(*_GRANTING), ident, pol, apply], help="request access"
    )
    r.add_argument("--dataset", required=True)
    r.add_argument("--table", required=True, help="schema.table")
    r.add_argument("--columns", required=True, help="comma-separated")
    r.add_argument("--row-filter")
    r.add_argument("--duration", required=True, help="e.g. 30m, 2h")
    r.add_argument("--purpose", required=True)
    r.add_argument("--pending-ttl", default="24h", help="two-person: how long a request waits")
    r.set_defaults(fn=cmd_request)

    ap = sub.add_parser(
        "approve", parents=[*only(*_GRANTING), ident, pol, apply], help="approve a pending request"
    )
    ap.add_argument("request_id")
    ap.set_defaults(fn=cmd_approve)

    g = sub.add_parser("grant", help="inspect grants").add_subparsers(dest="sub", required=True)
    gl = g.add_parser("list", parents=only("json", "dsn"), help="list active grants")
    gl.add_argument("--all", action="store_true", help="include revoked/expired")
    gl.set_defaults(fn=cmd_grant_list)
    gs = g.add_parser("status", parents=only("json", "dsn"), help="show one grant")
    gs.add_argument("grant_id")
    gs.set_defaults(fn=cmd_grant_status)

    rv = sub.add_parser("revoke", parents=[*only(*_REVOKING), apply], help="revoke a grant now")
    rv.add_argument("grant_id")
    rv.set_defaults(fn=cmd_revoke)
    sub.add_parser(
        "sweep",
        parents=[*only(*_REVOKING), apply],
        help="revoke expired grants (run on a schedule)",
    ).set_defaults(fn=cmd_sweep)

    rc = sub.add_parser("receipts", help="receipt tools").add_subparsers(dest="sub", required=True)
    v = rc.add_parser(
        "verify",
        parents=only("json", "signing_key", "receipt_log", "receipt_sink"),
        help="verify signatures and the hash chain",
    )
    v.add_argument(
        "--sink",
        dest="receipt_sink",
        default=argparse.SUPPRESS,
        help="also compare the local head with this sink (same as --receipt-sink)",
    )
    v.add_argument("--pubkey", help="public key hex, or a file containing it")
    v.add_argument("--expect-head", help="head hash recorded earlier (detects truncation)")
    v.set_defaults(fn=cmd_receipts_verify)
    pu = rc.add_parser(
        "push",
        parents=[*only("json", "receipt_log", "receipt_sink"), apply],
        help="send pending receipts to the external sink (dry run; --apply sends)",
    )
    pu.set_defaults(fn=cmd_receipts_push)

    sub.add_parser(
        "preflight",
        parents=[*only("json", "dsn"), apply],
        help="check state and warn on PUBLIC defaults (dry run; --apply creates state)",
    ).set_defaults(fn=cmd_preflight)
    return p


def _accepts(args: argparse.Namespace) -> set[str]:
    fn = args.fn
    table: dict[Any, tuple[str, ...]] = {
        cmd_keys_init: ("signing_key", "hash_key"),
        cmd_keys_export: ("signing_key",),
        cmd_request: _GRANTING,
        cmd_approve: _GRANTING,
        cmd_revoke: _REVOKING,
        cmd_sweep: _REVOKING,
        cmd_receipts_verify: ("signing_key", "receipt_log", "receipt_sink"),
        cmd_receipts_push: ("receipt_log", "receipt_sink"),
        cmd_grant_list: ("dsn",),
        cmd_grant_status: ("dsn",),
        cmd_preflight: ("dsn",),
    }
    return set(table.get(fn, ()))


def main(argv: Sequence[str] | None = None, out: Callable[[str], None] = print) -> int:
    from datagrant.pg.grant import GrantError
    from datagrant.pg.mask import MaskError
    from datagrant.policy import PolicyError
    from datagrant.receipt import ReceiptError
    from datagrant.rowfilter import RowFilterError

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse: 0 for --help/--version, 2 for usage errors
        return int(exc.code or 0)
    unused = [
        f"--{n.replace('_', '-')}"
        for n in ("dsn", "signing_key", "hash_key", "receipt_log", *_SINK)
        if getattr(args, n, None) is not None and n not in _accepts(args)
    ]
    if unused:
        print(
            f"datagrant: error: {', '.join(unused)} does not apply to this command", file=sys.stderr
        )
        return EXIT_USAGE
    if getattr(args, "apply", False) and getattr(args, "dry_run", False):
        print("datagrant: error: --apply and --dry-run conflict", file=sys.stderr)
        return EXIT_USAGE
    ctx = Ctx(args, out)
    if "receipt_sink" in _accepts(args):
        from datagrant.sink import SinkConfigError, sink_from_config

        try:
            mode = getattr(args, "receipt_sink_mode", None)
            args._remote = sink_from_config(getattr(args, "receipt_sink", None), mode)
        except SinkConfigError as exc:
            _err(ctx, _hide_token(str(exc)), EXIT_USAGE)
            return EXIT_USAGE
    dsn = getattr(args, "dsn", None) or os.environ.get(DSN_ENV)
    try:
        return int(args.fn(ctx))
    except CliError as exc:
        _err(ctx, redact(str(exc), dsn), exc.code)
        return exc.code
    except (
        PolicyError,
        KeyFileError,
        GrantError,
        MaskError,
        ReceiptError,
        RowFilterError,
        OSError,
    ) as exc:
        msg = str(exc) if not isinstance(exc, OSError) else f"{exc.strerror}: {exc.filename}"
        _err(ctx, redact(msg, dsn), EXIT_FAILED)
        return EXIT_FAILED
    except Exception as exc:  # noqa: BLE001 - psycopg and friends: redact, never echo DSN
        _err(ctx, redact(f"{type(exc).__name__}: {exc}", dsn), EXIT_FAILED)
        return EXIT_FAILED


def _err(ctx: Ctx, msg: str, code: int) -> None:
    msg = _hide_token(msg)
    if ctx.json:
        ctx.out(json.dumps({"error": msg, "exit_code": code}))
    else:
        print(f"datagrant: error: {msg}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
