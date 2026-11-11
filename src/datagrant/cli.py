"""datagrant command line (unit U6).

Exit codes: 0 ok, 1 denied/failed, 2 usage, 3 receipt could not be written
(a grant/request change still happened, or a denial receipt could not be
written so nothing was issued), 4 revoke failed (grant still active; retried
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
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

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


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PW_KV = re.compile(r"(password\s*=\s*)('(?:[^'\\]|\\.)*'|\S+)", re.IGNORECASE)
_PW_URL = re.compile(r"(\w+://[^:/@\s]*:)[^@\s]*@")


def redact(text: str, dsn: str | None = None) -> str:
    """Remove passwords from DSN/conninfo forms; also replace extracted passwords of length >= 4."""
    if dsn:
        try:
            import psycopg

            pw = psycopg.conninfo.conninfo_to_dict(dsn).get("password")
        except Exception:  # noqa: BLE001 - malformed DSN: fall back to patterns
            pw = None
        # Length < 4 matches common English fragments ("er", "in", "db") and
        # would mangle diagnostics if replaced globally. URI user:pass@ and
        # password= forms are still stripped below at every length.
        if isinstance(pw, str) and len(pw) >= 4:
            text = text.replace(pw, "***")
    return _PW_URL.sub(r"\1***@", _PW_KV.sub(r"\1***", text))


@dataclass
class Ctx:
    args: argparse.Namespace
    out: Callable[[str], None]
    oidc_token: str | None = None

    @property
    def json(self) -> bool:
        return bool(self.args.json)

    def emit(self, data: dict[str, Any], text: str) -> None:
        self.out(json.dumps(data, sort_keys=True, default=str) if self.json else text)


def _identity(args: argparse.Namespace) -> tuple[str, str]:
    if getattr(args, "as_user", None):
        return args.as_user, "flag"
    return getpass.getuser(), "os"


def _resolve_caller(ctx: Ctx, policy: Any) -> Any:
    """Resolve and verify the caller against ``policy.identity`` (local or OIDC)."""
    from datagrant.oidc import (
        OIDC_TOKEN_ENV,
        VerifiedIdentity,
        normalize_principal,
        read_token_file,
        verify_oidc_token,
    )

    args = ctx.args
    as_user = getattr(args, "as_user", None)
    token_file = getattr(args, "oidc_token_file", None)
    cfg = policy.identity
    if cfg.mode == "local":
        if token_file is not None:
            raise CliError(
                "--oidc-token-file cannot be used when policy.identity.mode is 'local'",
                EXIT_USAGE,
            )
        user, source = _identity(args)
        return VerifiedIdentity(username=normalize_principal(user), source=source)

    if as_user is not None:
        raise CliError(
            "--as-user is not allowed when policy.identity.mode is 'oidc'",
            EXIT_USAGE,
        )
    if token_file is not None:
        raw_token = read_token_file(token_file)
        ctx.oidc_token = raw_token
    else:
        env_tok = os.environ.get(OIDC_TOKEN_ENV)
        if not env_tok or not env_tok.strip():
            raise CliError(
                f"no OIDC token: pass --oidc-token-file or set ${OIDC_TOKEN_ENV}",
                EXIT_USAGE,
            )
        raw_token = env_tok
        ctx.oidc_token = raw_token
    return verify_oidc_token(raw_token, cfg)


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


def _pid_list(pids: tuple[int, ...]) -> str:
    return ", ".join(str(p) for p in pids) if pids else "unknown"


@contextmanager
def _pg_session(
    args: argparse.Namespace,
    *,
    lock: bool,
    wait: bool = True,
    ctx: Ctx | None = None,
) -> Iterator[Any]:
    """Connect; take the session advisory lock on mutating ``--apply`` only.

    Access-creating paths wait (bounded), then fail closed. revoke/sweep
    pass ``wait=False`` (try-lock) and proceed without the lock on contention.
    """
    from datagrant.pg.lock import LockBusy, holder_pids, lock_busy_message, session_lock

    with _connect(args) as conn:
        if not lock:
            yield conn
            return
        if wait:
            try:
                with session_lock(conn, wait=True):
                    yield conn
            except LockBusy as exc:
                raise CliError(lock_busy_message(exc.pids), EXIT_RECEIPT) from None
            return
        with session_lock(conn, wait=False) as acquired:
            if not acquired:
                msg = (
                    "proceeding without the datagrant lock; held by pid "
                    + _pid_list(holder_pids(conn))
                )
                if ctx is not None:
                    _warn(ctx, msg)
                else:
                    print(f"datagrant: warning: {msg}", file=sys.stderr)
            yield conn


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


def _hide_token(text: str, extra_oidc_token: str | None = None) -> str:
    from datagrant.oidc import OIDC_TOKEN_ENV, redact_token
    from datagrant.sink import SINK_TOKEN_ENV

    tok = os.environ.get(SINK_TOKEN_ENV)
    out = text.replace(tok, "***") if tok else text
    out = redact_token(out, os.environ.get(OIDC_TOKEN_ENV))
    return redact_token(out, extra_oidc_token)


def _warn(ctx: Ctx, msg: str) -> None:
    print(f"datagrant: warning: {_hide_token(msg, ctx.oidc_token)}", file=sys.stderr)


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
    from datagrant.oidc import INSECURE_LOCALHOST_ENV, allow_insecure_localhost
    from datagrant.policy import load_policy

    p = load_policy(ctx.args.file)
    warnings: list[str] = []
    if allow_insecure_localhost() and p.identity.mode == "oidc":
        msg = f"{INSECURE_LOCALHOST_ENV}=1 is set: insecure http:// localhost OIDC URLs are enabled"
        warnings.append(msg)
        _warn(ctx, msg)
    tables = sum(len(d.tables) for d in p.datasets.values())
    payload: dict[str, Any] = {
        "ok": True,
        "sha256": p.sha256,
        "approval": p.approval,
        "datasets": sorted(p.datasets),
        "tables": tables,
    }
    if warnings:
        payload["warnings"] = warnings
    ctx.emit(
        payload,
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


def _concurrent_reason(conn: Any, policy: Any, requester: str, dataset: str) -> str | None:
    cap = policy.concurrent_grant_cap(dataset)
    if cap is None:
        return None
    from psycopg.errors import UndefinedTable

    from datagrant.pg.grant import count_active_grants

    try:
        n = count_active_grants(conn, requester)
    except UndefinedTable:
        n = 0
    if n >= cap:
        return (
            f"requester {requester!r} already has {n} active grant(s) "
            f"(max_concurrent_grants is {cap})"
        )
    return None


def _redact_text(ctx: Ctx, text: str) -> str:
    dsn = getattr(ctx.args, "dsn", None) or os.environ.get(DSN_ENV)
    return _hide_token(redact(text, dsn), ctx.oidc_token)


def _redacted_reasons(ctx: Ctx, reasons: Sequence[str]) -> list[str]:
    return [_redact_text(ctx, str(r)) for r in reasons]


def _table_rule(policy: Any, req: Any) -> Any:
    if policy is None:
        return None
    ds = getattr(policy, "datasets", {}).get(req.dataset)
    if ds is None:
        return None
    return ds.tables.get(req.table)


def _receipt_reasons(reasons: Sequence[str]) -> list[str]:
    """Drop requester-supplied column names from reasons stored on a receipt."""
    out: list[str] = []
    for r in reasons:
        if r.startswith("columns not allowed:"):
            out.append("columns not allowed (see details.unknown_column_count)")
        else:
            out.append(r)
    return out


def _audit_facts(
    ctx: Ctx,
    req: Any,
    policy: Any,
    *,
    identity: Any = None,
    approvers: Sequence[str] = (),
    approver_identities: Sequence[Any] | None = None,
    starts_at: datetime | None = None,
    expires_at: datetime | None = None,
    policy_sha256: str | None = None,
    approval: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    from datagrant.receipt import GrantFacts

    now = datetime.now(UTC)
    extra: dict[str, Any] = {}
    rule = _table_rule(policy, req)
    if policy is None:
        cols: tuple[str, ...] = tuple(req.columns)
        masks: dict[str, str] = {c: "unknown" for c in cols}
        row_filter = req.row_filter
    else:
        if rule is None:
            known: list[str] = []
            unknown = list(req.columns)
            masks = {}
        else:
            known = [c for c in req.columns if c in rule.columns]
            unknown = [c for c in req.columns if c not in rule.columns]
            masks = {c: rule.columns[c] for c in known}
        cols = tuple(known)
        if unknown:
            extra["unknown_column_count"] = len(unknown)
        if req.row_filter is None:
            row_filter = None
        elif rule is not None and req.row_filter in rule.row_filters:
            row_filter = req.row_filter
        else:
            row_filter = None
            extra["row_filter_unlisted"] = True
    return GrantFacts(
        "",
        req.requester,
        req.dataset,
        req.table,
        cols,
        masks,
        row_filter,
        _redact_text(ctx, req.purpose),
        starts_at or now,
        expires_at or (now + req.duration),
        policy_sha256 if policy_sha256 is not None else policy.sha256,
        getattr(policy, "version", 1) if policy is not None else 1,
        approval if approval is not None else getattr(policy, "approval", "two-person"),
        tuple(approvers),
        dict(identity) if identity is not None else None,
        tuple(dict(x) for x in approver_identities) if approver_identities is not None else None,
    ), extra


def _write_decision_receipt(ctx: Ctx, event: str, facts: Any, details: dict[str, Any]) -> None:
    """Append a denial/expiry receipt. Missing key or write failure is exit 3."""
    from datagrant.receipt import ReceiptError

    try:
        sink = _sink(ctx.args)
    except KeyFileError as exc:
        raise CliError(str(exc), EXIT_RECEIPT) from None
    try:
        receipt.append(
            sink.log,
            event,  # type: ignore[arg-type]
            facts,
            sink.key,
            host=sink.host,
            details=details,
        )
    except ReceiptError as exc:
        raise CliError(str(exc), EXIT_RECEIPT) from None
    _deliver_quick(ctx, sink)


def _refuse_request(ctx: Ctx, req: Any, policy: Any, reasons: Sequence[str], caller: Any) -> int:
    safe = _redacted_reasons(ctx, reasons)
    ctx.emit(
        {"allowed": False, "reasons": safe, "requester": req.requester},
        "denied:\n" + "\n".join(f"  - {r}" for r in safe),
    )
    if ctx.args.apply:
        facts, extra = _audit_facts(ctx, req, policy, identity=caller.receipt_dict())
        _write_decision_receipt(
            ctx,
            "denied",
            facts,
            {"reasons": _receipt_reasons(safe), "phase": "request", **extra},
        )
    return EXIT_FAILED


def _identity_from_pending(pending: Any) -> dict[str, Any] | None:
    meta = getattr(pending, "requester_identity", None)
    if isinstance(meta, dict) and "source" in meta:
        return {k: v for k, v in meta.items() if k in ("source", "iss", "sub", "token_sha256")}
    return None


def _write_not_approved(
    ctx: Ctx, pending: Any, policy: Any, reasons: Sequence[str], caller: Any
) -> None:
    """Write a not_approved receipt on --apply. Raises CliError(EXIT_RECEIPT) on failure."""
    if not ctx.args.apply:
        return
    facts, extra = _audit_facts(
        ctx,
        pending.request,
        policy,
        identity=_identity_from_pending(pending),
        approvers=(caller.username,),
        approver_identities=(caller.approver_receipt_dict(),),
        starts_at=pending.created_at,
        expires_at=pending.expires_at,
    )
    _write_decision_receipt(
        ctx,
        "not_approved",
        facts,
        {
            "reasons": _receipt_reasons(list(reasons)),
            "phase": "approve",
            "request_id": pending.id,
            **extra,
        },
    )


def _refuse_approve(
    ctx: Ctx, pending: Any, policy: Any, reasons: Sequence[str], caller: Any
) -> int:
    safe = _redacted_reasons(ctx, reasons)
    ctx.emit(
        {"approved": False, "reasons": safe},
        "not approved:\n" + "\n".join(f"  - {r}" for r in safe),
    )
    _write_not_approved(ctx, pending, policy, safe, caller)
    return EXIT_FAILED


def _vote_receipt_ident(vote: Mapping[str, Any]) -> dict[str, str]:
    raw_ident = vote.get("identity")
    ident: Mapping[str, Any] = raw_ident if isinstance(raw_ident, dict) else {}
    out: dict[str, str] = {}
    if isinstance(vote.get("approver"), str):
        out["approver"] = vote["approver"]
    for k in ("approver", "source", "iss", "sub", "token_sha256"):
        v = ident.get(k)
        if isinstance(v, str) and k not in out:
            out[k] = v
    return out


def _facts_from_pending(ctx: Ctx, pending: Any) -> tuple[Any, dict[str, Any]]:
    return _audit_facts(
        ctx,
        pending.request,
        None,
        identity=_identity_from_pending(pending),
        starts_at=pending.created_at,
        expires_at=pending.expires_at,
        policy_sha256=pending.policy_sha256,
        approval="two-person",
    )


_DEFAULT_PENDING_TTL = timedelta(hours=24)


def _request_pending_ttl(policy: Any, pending_ttl_flag: str | None) -> timedelta:
    """Resolve two-person pending TTL. Auto mode ignores the flag and the cap."""
    from datagrant.policy import parse_duration

    if policy.approval != "two-person":
        return _DEFAULT_PENDING_TTL
    cap = policy.pending_ttl
    if pending_ttl_flag is None:
        if cap is not None and cap < _DEFAULT_PENDING_TTL:
            return cap
        return _DEFAULT_PENDING_TTL
    ttl = parse_duration(pending_ttl_flag, "--pending-ttl")
    if cap is not None and ttl > cap:
        raise CliError(
            f"--pending-ttl {pending_ttl_flag} exceeds policy.pending_ttl",
            EXIT_USAGE,
        )
    return ttl


def cmd_request(ctx: Ctx) -> int:
    from datagrant.pg.grant import build_plan, ensure_state, new_password
    from datagrant.pg.mask import inspect_table
    from datagrant.pg.requests import create_request
    from datagrant.pg.scram import scram_verifier
    from datagrant.policy import Request, evaluate, parse_duration

    a = ctx.args
    policy = _policy(a)
    ttl = _request_pending_ttl(policy, a.pending_ttl)
    caller = _resolve_caller(ctx, policy)
    user, source = caller.username, caller.source
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
    decision = evaluate(policy, req, extra_groups=caller.mapped_groups)
    if not decision.allowed:
        return _refuse_request(ctx, req, policy, decision.reasons, caller)
    two_person = decision.approval == "two-person"
    hash_key = (
        load_hash_key(resolve_key_path("hash", a.hash_key)) if _needs_hash(decision, cols) else None
    )
    with _pg_session(a, lock=bool(a.apply)) as conn:
        catalog = inspect_table(conn, req.table)
        if a.apply:
            sink = _sink(a)  # no signing key, no grant
            _check_outbox(ctx, sink)
            ensure_state(conn)
        cap_reason = _concurrent_reason(conn, policy, user, req.dataset)
        if cap_reason:
            return _refuse_request(ctx, req, policy, [cap_reason], caller)
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
                requester_identity=caller.receipt_dict(),
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
        password = new_password()
        if two_person:
            pending = create_request(
                conn,
                req,
                policy_sha256=policy.sha256,
                verifier=scram_verifier(password),
                ttl=ttl,
                requester_identity=caller.request_state_dict(),
            )
            n_req = policy.approvals_required
            ctx.emit(
                {
                    "status": "pending",
                    "request_id": pending.id,
                    "requester": user,
                    "identity_source": source,
                    "pending_expires_at": pending.expires_at,
                    "password": password,
                    "approvals_recorded": 0,
                    "approvals_required": n_req,
                    "approvals": f"0/{n_req}",
                },
                f"request {pending.id} is pending approval by another person"
                f" (approvals 0/{n_req}, expires {pending.expires_at.isoformat()}).\n"
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
            requester_identity=caller.receipt_dict(),
            approver_identities=(),
        )
        from datagrant.pg.grant import apply_plan

        apply_plan(conn, plan, sink)
        _deliver_issued(ctx, conn, plan, sink)
    return _print_grant(ctx, plan, password, user, source)


def _print_grant(
    ctx: Ctx,
    plan: Any,
    password: str | None,
    user: str,
    source: str,
    *,
    approvals_recorded: int | None = None,
    approvals_required: int | None = None,
) -> int:
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
    if approvals_recorded is not None and approvals_required is not None:
        data["approvals_recorded"] = approvals_recorded
        data["approvals_required"] = approvals_required
        data["approvals"] = f"{approvals_recorded}/{approvals_required}"
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
    from datagrant.pg.requests import (
        already_voted,
        drop_approval,
        eligible_votes,
        get_request,
        mapped_groups_of,
        record_approval,
    )
    from datagrant.policy import evaluate

    a = ctx.args
    policy = _policy(a)
    caller = _resolve_caller(ctx, policy)
    approver, source = caller.username, caller.source
    with _pg_session(a, lock=bool(a.apply)) as conn:
        if a.apply:
            ensure_state(conn)
        pending = get_request(conn, a.request_id)
        if pending.status != "pending" or pending.verifier is None:
            return _refuse_approve(
                ctx,
                pending,
                policy,
                [f"request {pending.id} is {pending.status}, not pending"],
                caller,
            )
        req_meta = pending.requester_identity
        req_mode = req_meta.get("mode", "local") if isinstance(req_meta, dict) else "local"
        if req_mode != policy.identity.mode:
            msg = (
                f"request {pending.id} was created with identity mode {req_mode!r},"
                f" but current policy uses {policy.identity.mode!r}"
            )
            _write_not_approved(ctx, pending, policy, _redacted_reasons(ctx, [msg]), caller)
            raise CliError(msg, EXIT_FAILED)
        if policy.identity.mode == "oidc":
            if (
                not isinstance(req_meta, dict)
                or req_meta.get("source") != "oidc"
                or not isinstance(req_meta.get("iss"), str)
                or not req_meta["iss"]
                or not isinstance(req_meta.get("sub"), str)
                or not req_meta["sub"]
                or not isinstance(req_meta.get("token_sha256"), str)
                or not _HEX64_RE.fullmatch(req_meta["token_sha256"])
            ):
                msg = f"request {pending.id} is missing valid verified OIDC metadata"
                _write_not_approved(ctx, pending, policy, _redacted_reasons(ctx, [msg]), caller)
                raise CliError(msg, EXIT_FAILED)
            if req_meta["iss"] != policy.identity.issuer:
                msg = (
                    f"request {pending.id} was issued by {req_meta['iss']!r},"
                    f" which does not match policy.identity.issuer {policy.identity.issuer!r}"
                )
                _write_not_approved(ctx, pending, policy, _redacted_reasons(ctx, [msg]), caller)
                raise CliError(msg, EXIT_FAILED)
            if req_meta.get("username_claim") != policy.identity.username_claim:
                msg = (
                    f"request {pending.id} used username_claim={req_meta.get('username_claim')!r},"
                    f" which does not match policy.identity.username_claim"
                    f" {policy.identity.username_claim!r}"
                )
                _write_not_approved(ctx, pending, policy, _redacted_reasons(ctx, [msg]), caller)
                raise CliError(msg, EXIT_FAILED)
        reasons = policy.can_approve(
            approver, pending.request.requester, extra_groups=caller.mapped_groups
        )
        if (
            policy.identity.mode == "oidc"
            and isinstance(req_meta, dict)
            and (caller.iss, caller.sub) == (req_meta.get("iss"), req_meta.get("sub"))
            and "approver must be a different person than the requester" not in reasons
        ):
            reasons.insert(0, "approver must be a different person than the requester")
        # Re-check requester's recorded IdP groups against CURRENT policy's allowed_groups
        # and group_map ONLY when stored groups_claim matches current policy.identity.groups_claim.
        req_extra: frozenset[str] = frozenset()
        if policy.identity.mode == "oidc" and isinstance(req_meta, dict):
            same_gclaim = (
                "groups_claim" in req_meta
                and req_meta.get("groups_claim") == policy.identity.groups_claim
            )
            raw_idp_g = req_meta.get("idp_groups", ()) if same_gclaim else ()
            idp_gs = (
                [g for g in raw_idp_g if isinstance(g, str)] if isinstance(raw_idp_g, list) else []
            )
            if policy.identity.allowed_groups and not (
                set(idp_gs) & policy.identity.allowed_groups
            ):
                reasons.append(
                    "request no longer allowed: requester is not in policy.identity.allowed_groups"
                )
            req_extra = frozenset(
                policy.identity.group_map[g] for g in idp_gs if g in policy.identity.group_map
            )
        decision = evaluate(policy, pending.request, extra_groups=req_extra)
        if not decision.allowed:
            reasons += [f"request no longer allowed: {r}" for r in decision.reasons]
        ds = policy.datasets.get(pending.request.dataset)
        rule = ds.tables.get(pending.request.table) if ds is not None else None
        if rule is not None:
            reasons.extend(
                policy.sod_reasons(
                    pending.request.requester,
                    approver,
                    rule.allowed_groups,
                    requester_extra=req_extra,
                    approver_extra=caller.mapped_groups,
                )
            )
        if reasons:
            return _refuse_approve(ctx, pending, policy, reasons, caller)
        cap_reason = _concurrent_reason(
            conn, policy, pending.request.requester, pending.request.dataset
        )
        if cap_reason:
            return _refuse_approve(ctx, pending, policy, [cap_reason], caller)
        req_receipt_ident: dict[str, Any] = (
            {k: v for k, v in req_meta.items() if k in ("source", "iss", "sub", "token_sha256")}
            if isinstance(req_meta, dict) and "source" in req_meta
            else {"source": "os"}
        )
        required = policy.approvals_required
        ident = caller.approver_receipt_dict()
        issuer = policy.identity.issuer if policy.identity.mode == "oidc" else None

        def _voter_ok(vote: Mapping[str, Any]) -> bool:
            name = vote.get("approver")
            if not isinstance(name, str):
                return False
            extra = mapped_groups_of(vote)
            return not policy.can_approve(
                name, pending.request.requester, extra_groups=extra
            )

        counted, _ignored = eligible_votes(
            pending.approvals,
            policy_sha256=policy.sha256,
            issuer=issuer,
            can_approve=_voter_ok,
        )
        already = already_voted(counted, approver, ident)
        projected = len(counted) if already else len(counted) + 1
        would_issue = projected >= required
        voter_names = [str(v.get("approver")) for v in counted]
        voter_idents = [_vote_receipt_ident(v) for v in counted]
        if not already:
            voter_names.append(approver)
            voter_idents.append(ident)
        app_receipt_idents = tuple(voter_idents)
        cols = pending.request.columns
        hash_key = (
            load_hash_key(resolve_key_path("hash", a.hash_key))
            if _needs_hash(decision, cols)
            else None
        )
        if not a.apply:
            if would_issue:
                plan = build_plan(
                    decision,
                    pending.request,
                    database=policy.datasets[pending.request.dataset].database,
                    password="",  # nosec B106 - dry run: no password exists
                    verifier=REDACTED,
                    catalog=inspect_table(conn, pending.request.table),
                    hash_key=hash_key,
                    approvers=tuple(voter_names),
                    requester_identity=req_receipt_ident,
                    approver_identities=app_receipt_idents,
                )
                sqls = _redacted_sql(plan)
                ctx.emit(
                    {
                        "dry_run": True,
                        "request_id": pending.id,
                        "approver": approver,
                        "sql": sqls,
                        "approvals_recorded": projected,
                        "approvals_required": required,
                        "would_issue": True,
                        "already_approved": already,
                    },
                    f"dry run: {approver} may approve request {pending.id}"
                    f" (approvals {projected}/{required}); with --apply:\n"
                    + "\n".join(x + ";" for x in sqls),
                )
            else:
                ctx.emit(
                    {
                        "dry_run": True,
                        "request_id": pending.id,
                        "approver": approver,
                        "approvals_recorded": projected,
                        "approvals_required": required,
                        "would_issue": False,
                        "already_approved": already,
                    },
                    f"dry run: {approver} would record approval {projected} of {required}"
                    f" for request {pending.id}; with --apply no grant yet",
                )
            return EXIT_OK
        sink = _sink(a)
        _check_outbox(ctx, sink)
        if required <= 1:
            plan = build_plan(
                decision,
                pending.request,
                database=policy.datasets[pending.request.dataset].database,
                password=new_password(),
                verifier=pending.verifier,
                catalog=inspect_table(conn, pending.request.table),
                hash_key=hash_key,
                approvers=(approver,),
                requester_identity=req_receipt_ident,
                approver_identities=(ident,),
            )
            apply_plan(conn, plan, sink, request_id=pending.id, approver=approver)
            _deliver_issued(ctx, conn, plan, sink)
            return _print_grant(
                ctx,
                plan,
                None,
                pending.request.requester,
                source,
                approvals_recorded=1,
                approvals_required=1,
            )

        result = record_approval(
            conn,
            pending.id,
            approver=approver,
            identity=ident,
            required=required,
            policy_sha256=policy.sha256,
            issuer=issuer,
            can_approve=_voter_ok,
            persist_if_final=False,
            mapped_groups=tuple(sorted(caller.mapped_groups)),
        )
        if result.is_final:
            counted_final, _ign = eligible_votes(
                result.pending.approvals,
                policy_sha256=policy.sha256,
                issuer=issuer,
                can_approve=_voter_ok,
            )
            names = tuple(str(v.get("approver")) for v in counted_final)
            idents = tuple(_vote_receipt_ident(v) for v in counted_final)
            issued = build_plan(
                decision,
                pending.request,
                database=policy.datasets[pending.request.dataset].database,
                password=new_password(),
                verifier=pending.verifier,
                catalog=inspect_table(conn, pending.request.table),
                hash_key=hash_key,
                approvers=names,
                requester_identity=req_receipt_ident,
                approver_identities=idents,
            )
            incoming: tuple[dict[str, Any], ...] = ()
            if result.added:
                incoming = tuple(
                    dict(v)
                    for v in result.pending.approvals
                    if already_voted([v], approver, ident)
                )
            apply_plan(
                conn,
                issued,
                sink,
                request_id=pending.id,
                approver=approver,
                approvals=incoming,
                required=required,
                policy_sha256=policy.sha256,
                issuer=issuer,
                can_approve=_voter_ok,
            )
            _deliver_issued(ctx, conn, issued, sink)
            return _print_grant(
                ctx,
                issued,
                None,
                pending.request.requester,
                source,
                approvals_recorded=len(issued.facts.approvers) if issued.facts else required,
                approvals_required=required,
            )
        extra_ignored = (
            {"ignored_approvals": list(result.ignored)} if result.ignored else {}
        )
        if result.already:
            ctx.emit(
                {
                    "status": "pending",
                    "request_id": pending.id,
                    "already_approved": True,
                    "approvals_recorded": result.recorded,
                    "approvals_required": result.required,
                    "approvals": f"{result.recorded}/{result.required}",
                    **extra_ignored,
                },
                f"{approver} already approved request {pending.id}"
                f" ({result.recorded}/{result.required})",
            )
            return EXIT_OK
        counted_partial, _ign_partial = eligible_votes(
            result.pending.approvals,
            policy_sha256=policy.sha256,
            issuer=issuer,
            can_approve=_voter_ok,
        )
        try:
            facts, extra = _audit_facts(
                ctx,
                pending.request,
                policy,
                identity=_identity_from_pending(pending),
                approvers=tuple(str(v.get("approver")) for v in counted_partial),
                approver_identities=tuple(
                    _vote_receipt_ident(v) for v in counted_partial
                ),
                starts_at=pending.created_at,
                expires_at=pending.expires_at,
            )
            _write_decision_receipt(
                ctx,
                "approval_recorded",
                facts,
                {
                    "request_id": pending.id,
                    "approvals_recorded": result.recorded,
                    "approvals_required": result.required,
                    "phase": "approve",
                    **extra,
                },
            )
        except CliError:
            drop_approval(conn, pending.id, approver=approver, identity=ident)
            raise
        ignored_note = (
            f"; not counted: {', '.join(result.ignored)}" if result.ignored else ""
        )
        ctx.emit(
            {
                "status": "pending",
                "request_id": pending.id,
                "approvals_recorded": result.recorded,
                "approvals_required": result.required,
                "approvals": f"{result.recorded}/{result.required}",
                **extra_ignored,
            },
            f"approval recorded for request {pending.id}"
            f" ({result.recorded}/{result.required}){ignored_note}",
        )
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
    out = []
    for r in conn.execute(q, params).fetchall():
        row = dict(zip(_GRANT_COLS, r, strict=True))
        n = len(row.get("approvers") or [])
        row["approvals"] = f"{n}/{n}"
        out.append(row)
    return out


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
    with _pg_session(ctx.args, lock=True, wait=False, ctx=ctx) as conn:
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
    from datagrant.pg.requests import expire_stale_requests
    from datagrant.pg.revoke import sweep
    from datagrant.receipt import ReceiptError

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
    with _pg_session(ctx.args, lock=True, wait=False, ctx=ctx) as conn:
        ensure_state(conn)
        results = sweep(conn, sink)
        expired = expire_stale_requests(conn)
    expired_requests = [p.id for p in expired]
    request_receipt_error: str | None = None
    if expired:
        if sink is None:
            request_receipt_error = key_problem or "signing key unavailable"
        else:
            for pending in expired:
                try:
                    facts, extra = _facts_from_pending(ctx, pending)
                    receipt.append(
                        sink.log,
                        "request_expired",
                        facts,
                        sink.key,
                        host=sink.host,
                        details={"request_id": pending.id, **extra},
                    )
                except ReceiptError as exc:
                    request_receipt_error = str(exc)
    delivery = _deliver_quick(ctx, sink)
    lines = [
        f"grant {r.grant_id}: {r.outcome}"
        + (f" ({r.error})" if r.error else "")
        + (f" [receipt not written: {r.receipt_error}]" if r.receipt_error else "")
        for r in results
    ]
    lines += [f"request {rid}: expired" for rid in expired_requests]
    if key_problem and (results or expired_requests):
        lines.append(f"receipts not written: {key_problem}")
    elif request_receipt_error:
        lines.append(f"receipts not written: {request_receipt_error}")
    ctx.emit(
        {
            "results": [_result_dict(r) for r in results],
            "expired_requests": expired_requests,
            "key_problem": key_problem,
            "sink": delivery,
        },
        "\n".join(lines) or "nothing to sweep",
    )
    code = _exit_for(results, key_problem)
    if code == EXIT_OK and expired_requests and (key_problem or request_receipt_error):
        return EXIT_RECEIPT
    return code


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


def cmd_doctor(ctx: Ctx) -> int:
    from datagrant.doctor import STATUS_FAIL, run_doctor

    a = ctx.args
    dsn = a.dsn or os.environ.get(DSN_ENV)
    policy = a.policy or os.environ.get(POLICY_ENV)
    log = _log_path(a)

    def scrub(msg: str) -> str:
        return _hide_token(redact(msg, dsn), ctx.oidc_token)

    checks = run_doctor(
        signing_path=resolve_key_path("signing", a.signing_key),
        hash_path=resolve_key_path("hash", a.hash_key),
        policy_path=Path(policy) if policy else None,
        receipt_log=log,
        dsn=dsn,
        sink_configured=_remote(a) is not None,
        scrub=scrub,
    )
    ok = not any(c.status == STATUS_FAIL for c in checks)
    payload = {"ok": ok, "checks": [c.as_dict() for c in checks]}
    lines = [
        f"{c.name}: {c.status}" + (f": {c.detail}" if c.detail else "") for c in checks
    ]
    ctx.emit(payload, "\n".join(lines))
    return EXIT_OK if ok else EXIT_FAILED


def cmd_preflight(ctx: Ctx) -> int:
    from datagrant.pg.grant import ensure_state, preflight

    with _pg_session(ctx.args, lock=bool(ctx.args.apply)) as conn:
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
_DOCTOR = ("json", "dsn", "signing_key", "hash_key", "receipt_log", *_SINK)


class _SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with allow_abbrev=False and token/JWS-scrubbed usage errors."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        from datagrant.oidc import _JWS_LIKE_RE

        clean = _JWS_LIKE_RE.sub("<redacted>", _hide_token(message))
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {clean}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


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

    def only(*names: str, dir_help: bool = False) -> list[_SafeArgumentParser]:
        out = []
        for n in names:
            c = _SafeArgumentParser(add_help=False)
            flags, kw = with_dir[n] if dir_help and n in with_dir else opts[n]
            c.add_argument(*flags, **kw, **sup)
            out.append(c)
        return out

    ident = _SafeArgumentParser(add_help=False)
    ident.add_argument(
        "--as-user",
        help="act as this name instead of the OS user. NOT authentication: for automation/tests",
    )
    ident.add_argument(
        "--oidc-token-file",
        help="0600 file containing the caller's OIDC ID token (beats $DATAGRANT_OIDC_TOKEN)",
    )
    apply = _SafeArgumentParser(add_help=False)
    apply.add_argument(
        "--apply", action="store_true", help="make the change (default is a dry run)"
    )
    apply.add_argument(
        "--dry-run", action="store_true", help="no-op: dry run is already the default"
    )
    pol = _SafeArgumentParser(add_help=False)
    pol.add_argument("--policy", help=f"policy YAML (default ${POLICY_ENV})")

    p = _SafeArgumentParser(
        prog="datagrant",
        description="Just-in-time, expiring, masked access to regulated data, with receipts.",
    )
    for flags, kw in opts.values():
        p.add_argument(*flags, **kw)
    p.add_argument("--version", action="version", version=f"datagrant {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_SafeArgumentParser)

    keys = sub.add_parser("keys", help="create or export keys").add_subparsers(
        dest="sub", required=True, parser_class=_SafeArgumentParser
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

    pc = sub.add_parser("policy", help="policy tools").add_subparsers(
        dest="sub", required=True, parser_class=_SafeArgumentParser
    )
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
    r.add_argument(
        "--pending-ttl",
        default=None,
        metavar="TTL",
        help="two-person: how long a request waits (default 24h, or policy.pending_ttl if shorter)",
    )
    r.set_defaults(fn=cmd_request)

    ap = sub.add_parser(
        "approve", parents=[*only(*_GRANTING), ident, pol, apply], help="approve a pending request"
    )
    ap.add_argument("request_id")
    ap.set_defaults(fn=cmd_approve)

    g = sub.add_parser("grant", help="inspect grants").add_subparsers(
        dest="sub", required=True, parser_class=_SafeArgumentParser
    )
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

    rc = sub.add_parser("receipts", help="receipt tools").add_subparsers(
        dest="sub", required=True, parser_class=_SafeArgumentParser
    )
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
    sub.add_parser(
        "doctor",
        parents=[*only(*_DOCTOR), pol],
        help="read-only host and database checks (no --apply)",
    ).set_defaults(fn=cmd_doctor)
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
        cmd_doctor: _DOCTOR,
    }
    return set(table.get(fn, ()))


def main(argv: Sequence[str] | None = None, out: Callable[[str], None] = print) -> int:
    from datagrant.oidc import IdentityError
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
        IdentityError,
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
    msg = _hide_token(msg, ctx.oidc_token)
    if ctx.json:
        ctx.out(json.dumps({"error": msg, "exit_code": code}))
    else:
        print(f"datagrant: error: {msg}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
