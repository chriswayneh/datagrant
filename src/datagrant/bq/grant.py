"""BigQuery per-grant engine: authorized view, issuing-row fail-safe (PR 3a).

Order: issuing row, view in shared datagrant_views, authorize dataset only if
missing, names-row update, issued receipt, enabling, IAM last (stub in 3a),
active. Reverse-drop the view on failure; never de-authorize the standing
source entry. IAM JSON (resource.name, jobUser title, etag 409,
accessPolicyVersion=3) is PR 3b. CLI --apply stays refused.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from datagrant import receipt
from datagrant.keys import HashKey
from datagrant.pg.grant import ReceiptSink
from datagrant.policy import Decision, Request
from datagrant.receipt import GrantFacts
from datagrant.rowfilter import _KEYWORDS, MAX_DEPTH, RowFilterError, _tokenize

VIEW_DATASET = "datagrant_views"
STATE_DATASET = "datagrant"
HASH_UDF = "hash_hmac"
SRC_ALIAS = "SRC"
_GRANT_ID_RE = re.compile(r"^[0-9a-f]{12}$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,1023}$")
_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
REDACTED = "[REDACTED]"


class GrantError(RuntimeError):
    """Raised when a BigQuery grant cannot be planned or applied."""


@dataclass(frozen=True)
class GrantPlan:
    grant_id: str
    view_id: str
    view_sql: str
    project: str
    source_dataset: str
    source_table: str
    principal: str
    expires_at: datetime
    location: str | None = None
    facts: GrantFacts | None = None
    hash_key: HashKey | None = field(default=None, repr=False)


class GrantClient(Protocol):
    """Mocked in tests. IAM bind is a recorded stub until PR 3b."""

    def insert_issuing(self, plan: GrantPlan) -> None: ...
    def create_view(self, plan: GrantPlan) -> None: ...
    def authorize_views_dataset_if_missing(self, plan: GrantPlan) -> bool: ...
    def update_names(self, plan: GrantPlan) -> int: ...
    def claim_enabling(self, plan: GrantPlan) -> int: ...
    def bind_iam(self, plan: GrantPlan) -> None: ...
    def claim_active(self, plan: GrantPlan) -> int: ...
    def drop_view(self, plan: GrantPlan) -> None: ...
    def mark_failed(self, plan: GrantPlan) -> None: ...


def q(name: str) -> str:
    """Backtick-quote a BigQuery identifier. Rejects names outside the grammar."""
    if not _IDENT_RE.fullmatch(name):
        raise GrantError(f"unsafe identifier {name!r}")
    return "`" + name + "`"


def q_project(name: str) -> str:
    if not _PROJECT_RE.fullmatch(name):
        raise GrantError(f"unsafe GCP project id {name!r}")
    return "`" + name + "`"


def lit(value: str) -> str:
    """BigQuery string literal for DDL. Never interpolates raw text."""
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _src_col(col: str) -> str:
    return f"{q(SRC_ALIAS)}.{q(col)}"


def _split_table(table: str, default_dataset: str | None) -> tuple[str, str]:
    if "." in table:
        ds, name = table.split(".", 1)
        return ds, name
    if default_dataset:
        return default_dataset, table
    raise GrantError(f"table {table!r} needs a dataset id")


def _reject_controls(label: str, value: str) -> None:
    if _CTRL.search(value):
        raise GrantError(f"{label} contains NUL or control characters")


def _col_expr(col: str, mask: str, hash_scope: str) -> str:
    ident = q(col)
    src = _src_col(col)
    if mask == "passthrough":
        return f"{src} AS {ident}"
    if mask == "null":
        return f"CAST(NULL AS STRING) AS {ident}"
    if mask == "redact":
        return f"{lit(REDACTED)} AS {ident}"
    if mask == "partial":
        text = f"CAST({src} AS STRING)"
        return (
            f"CASE WHEN LENGTH({text}) >= 8 THEN "
            f"CONCAT(REPEAT('*', LENGTH({text}) - 4), RIGHT({text}, 4)) "
            f"ELSE REPEAT('*', LENGTH({text})) END AS {ident}"
        )
    if mask == "hash":
        fn = f"{q(STATE_DATASET)}.{q(HASH_UDF)}"
        return f"{fn}({lit(hash_scope)}, CAST({src} AS STRING)) AS {ident}"
    raise GrantError(f"unknown mask {mask!r}")


class _BqFilter:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.toks = tokens
        self.i = 0
        self.columns: set[str] = set()

    def _peek_word(self) -> str | None:
        if self.i < len(self.toks) and self.toks[self.i][0] == "word":
            return self.toks[self.i][1].lower()
        return None

    def _next(self, what: str) -> tuple[str, str]:
        if self.i >= len(self.toks):
            raise RowFilterError(f"unexpected end of filter, expected {what}")
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self) -> str:
        out = self.expr(0)
        if self.i != len(self.toks):
            raise RowFilterError(f"unexpected token {self.toks[self.i][1]!r}")
        return out

    def expr(self, depth: int) -> str:
        parts = [self.term(depth)]
        while self._peek_word() == "or":
            self.i += 1
            parts.append(self.term(depth))
        return parts[0] if len(parts) == 1 else " OR ".join(parts)

    def term(self, depth: int) -> str:
        parts = [self.factor(depth)]
        while self._peek_word() == "and":
            self.i += 1
            parts.append(self.factor(depth))
        return parts[0] if len(parts) == 1 else " AND ".join(parts)

    def factor(self, depth: int) -> str:
        if depth > MAX_DEPTH:
            raise RowFilterError("row filter nested too deeply")
        kind, val = self._next("a condition")
        if kind == "paren" and val == "(":
            inner = self.expr(depth + 1)
            if self._next("')'") != ("paren", ")"):
                raise RowFilterError("expected ')'")
            return f"({inner})"
        if kind != "word" or val.lower() in _KEYWORDS:
            raise RowFilterError(f"expected a column name, got {val!r}")
        self.columns.add(val)
        col = _src_col(val)
        if self._peek_word() == "is":
            self.i += 1
            neg = self._peek_word() == "not"
            if neg:
                self.i += 1
            if self._next("NULL")[1].lower() != "null":
                raise RowFilterError("expected NULL after IS")
            return f"{col} IS NOT NULL" if neg else f"{col} IS NULL"
        okind, op = self._next("a comparison operator")
        if okind != "op":
            raise RowFilterError(f"expected a comparison operator, got {op!r}")
        op = "<>" if op == "!=" else op
        return f"{col} {op} {self.literal()}"

    def literal(self) -> str:
        kind, val = self._next("a literal")
        if kind == "str":
            return lit(val[1:-1].replace("''", "'"))
        if kind == "num":
            return val
        if kind == "word" and val.lower() in ("true", "false"):
            return val.upper()
        raise RowFilterError(f"expected a literal, got {val!r}")


def render_row_filter(text: str) -> tuple[str, frozenset[str]]:
    """Re-emit a policy row filter as BigQuery SQL with `SRC`.`COL`."""
    p = _BqFilter(_tokenize(text))
    return p.parse(), frozenset(p.columns)


def view_select_sql(
    req: Request,
    masks: Mapping[str, str],
    *,
    project: str,
    source_dataset: str,
    hash_scope: str,
) -> str:
    """SELECT for G_<id>. Calls datagrant.hash_hmac; never embeds key bytes."""
    cols = ", ".join(_col_expr(c, masks[c], hash_scope) for c in req.columns)
    ds, table = _split_table(req.table, source_dataset)
    from_tbl = f"{q_project(project)}.{q(ds)}.{q(table)}"
    select = f"SELECT {cols} FROM {from_tbl} AS {q(SRC_ALIAS)}"  # nosec B608
    if req.row_filter is not None:
        try:
            cond, _used = render_row_filter(req.row_filter)
        except RowFilterError as exc:
            raise GrantError(str(exc)) from None
        select = f"{select} WHERE {cond}"  # nosec B608
    return select


def build_plan(
    decision: Decision,
    req: Request,
    *,
    project: str,
    principal: str,
    source_dataset: str | None = None,
    location: str | None = None,
    grant_id: str | None = None,
    now: datetime | None = None,
    approvers: Sequence[str] = (),
    hash_key: HashKey | None = None,
    requester_identity: Mapping[str, Any] | None = None,
    approver_identities: Sequence[Mapping[str, Any]] | None = None,
) -> GrantPlan:
    """Pure plan. IAM bind details are PR 3b; this only names the last step."""
    if not decision.allowed:
        raise GrantError("cannot build a grant for a denied decision")
    if not principal.strip():
        raise GrantError("google principal is required")
    _reject_controls("purpose", req.purpose)
    gid = grant_id or secrets.token_hex(6)
    if not _GRANT_ID_RE.fullmatch(gid):
        raise GrantError("grant id must be 12 lowercase hex characters")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise GrantError("now must be timezone-aware")
    expires = now + req.duration
    ds, _table = _split_table(req.table, source_dataset)
    needs_hash = any(decision.masks[c] == "hash" for c in req.columns)
    if needs_hash and hash_key is None:
        raise GrantError("hash masking requires a hash key file (see keys.hash_key_path)")
    scope = decision.hash_scope or req.dataset
    view_sql = view_select_sql(
        req, decision.masks, project=project, source_dataset=ds, hash_scope=scope
    )
    if hash_key is not None and hash_key.derived.hex() in view_sql + gid + principal:
        raise GrantError("hash key leaked into view SQL")
    view_id = f"{project}.{VIEW_DATASET}.G_{gid}"
    facts = GrantFacts(
        gid,
        req.requester,
        req.dataset,
        req.table,
        tuple(req.columns),
        {c: decision.masks[c] for c in req.columns},
        req.row_filter,
        req.purpose,
        now,
        expires,
        decision.policy_sha256,
        decision.policy_version,
        decision.approval,
        tuple(approvers),
        dict(requester_identity) if requester_identity is not None else None,
        tuple(dict(x) for x in approver_identities) if approver_identities is not None else None,
    )
    return GrantPlan(
        gid,
        view_id,
        view_sql,
        project,
        f"{project}.{ds}",
        req.table,
        principal.strip(),
        expires,
        location,
        facts,
        hash_key if needs_hash else None,
    )


def reverse_drop(client: GrantClient, plan: GrantPlan) -> None:
    """Drop the grant view. Do not de-authorize datagrant_views on the source."""
    client.drop_view(plan)
    client.mark_failed(plan)


def append_revoked(plan: GrantPlan, receipts: ReceiptSink | None, *, reason: str) -> None:
    if receipts is None or plan.facts is None:
        return
    try:
        receipt.append(
            receipts.log,
            "revoked",
            plan.facts,
            receipts.key,
            host=receipts.host,
            details={"engine": "bigquery", "reason": reason},
        )
    except Exception:  # noqa: BLE001, S110  # nosec B110
        pass


def apply_plan(
    client: GrantClient,
    plan: GrantPlan,
    receipts: ReceiptSink | None = None,
) -> None:
    """Fail-safe apply. IAM last is a client stub in 3a (filled in 3b)."""
    created = False
    issued = False
    try:
        client.insert_issuing(plan)
        created = True
        client.create_view(plan)
        client.authorize_views_dataset_if_missing(plan)
        if client.update_names(plan) != 1:
            reverse_drop(client, plan)
            raise GrantError(f"grant {plan.grant_id}: not issuing at row update; view dropped")
        if receipts is None:
            reverse_drop(client, plan)
            raise GrantError(f"grant {plan.grant_id}: issued receipt is required before IAM")
        if plan.facts is None:
            reverse_drop(client, plan)
            raise GrantError(f"grant {plan.grant_id}: plan has no receipt facts")
        try:
            receipt.append(
                receipts.log,
                "issued",
                plan.facts,
                receipts.key,
                host=receipts.host,
                details={"engine": "bigquery", "principal": plan.principal, "view": plan.view_id},
            )
            issued = True
        except BaseException as exc:
            reverse_drop(client, plan)
            if not isinstance(exc, Exception):
                raise
            raise GrantError(
                f"grant {plan.grant_id}: receipt not written ({exc}); view dropped"
            ) from exc
        if client.claim_enabling(plan) != 1:
            reverse_drop(client, plan)
            append_revoked(plan, receipts, reason="lost_issuing")
            raise GrantError(f"grant {plan.grant_id}: not issuing at IAM; view dropped")
        try:
            client.bind_iam(plan)
        except BaseException as exc:
            reverse_drop(client, plan)
            append_revoked(plan, receipts, reason="iam_failed")
            if not isinstance(exc, Exception):
                raise
            raise GrantError(f"grant {plan.grant_id}: IAM failed ({exc}); view dropped") from exc
        if client.claim_active(plan) != 1:
            reverse_drop(client, plan)
            append_revoked(plan, receipts, reason="lost_enabling")
            raise GrantError(f"grant {plan.grant_id}: not enabling after IAM; view dropped")
    except GrantError:
        raise
    except Exception as exc:
        if created:
            reverse_drop(client, plan)
            if issued:
                append_revoked(plan, receipts, reason="apply_failed")
        raise GrantError(f"grant {plan.grant_id} failed: {exc}") from exc
