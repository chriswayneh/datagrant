"""BigQuery per-grant engine: authorized view, issuing-row fail-safe (PR 3b).

Order: issuing row, view in shared datagrant_views, authorize dataset only if
missing, names-row update, issued receipt, enabling, IAM last, active.
IAM bind JSON: dataset resource.name of G_<id>, per-grant jobUser title G_<id>,
accessPolicyVersion=3, etag 409 retry. Reverse-drop unbinds this grant only.
CLI --apply stays refused.
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
_PRINCIPAL_PREFIXES = ("user:", "serviceAccount:", "group:")
_REFUSED_PRINCIPALS = frozenset({"allusers", "allauthenticatedusers"})
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+$")
ACCESS_POLICY_VERSION = 3
ETAG_MAX_TRIES = 2
JOB_USER_ROLE = "roles/bigquery.jobUser"
GRANTEE_ROLE_ID = "datagrantViewGetData"
GRANTEE_PERMISSIONS = ("bigquery.tables.getData",)
TABLE_RESOURCE_TYPE = "bigquery.googleapis.com/Table"
TABLE_RESOURCE_SERVICE = "bigquery.googleapis.com"


class GrantError(RuntimeError):
    """Raised when a BigQuery grant cannot be planned or applied."""


class ConflictError(GrantError):
    """HTTP 409 / ABORTED on an IAM set (stale etag)."""


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
    request_id: str | None = None


@dataclass
class IamPolicy:
    """IAM allow policy. version is accessPolicyVersion."""

    etag: str
    bindings: list[dict[str, Any]] = field(default_factory=list)
    version: int = ACCESS_POLICY_VERSION


class GrantClient(Protocol):
    """Mocked in tests. get/set IAM always send accessPolicyVersion and etag.

    ``unbind_iam`` and ``drop_view`` must succeed if the object does not exist.
    """

    def insert_issuing(self, plan: GrantPlan) -> None: ...
    def create_view(self, plan: GrantPlan) -> None: ...
    def authorize_views_dataset_if_missing(self, plan: GrantPlan) -> bool: ...
    def update_names(self, plan: GrantPlan) -> int: ...
    def claim_enabling(self, plan: GrantPlan) -> int: ...
    def get_dataset_iam(
        self, project: str, dataset: str, *, access_policy_version: int
    ) -> IamPolicy: ...
    def set_dataset_iam(
        self, project: str, dataset: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None: ...
    def get_project_iam(self, project: str, *, access_policy_version: int) -> IamPolicy: ...
    def set_project_iam(
        self, project: str, policy: IamPolicy, *, access_policy_version: int
    ) -> None: ...
    def bind_iam(self, plan: GrantPlan) -> None: ...
    def claim_active(self, plan: GrantPlan) -> int: ...
    def unbind_iam(self, plan: GrantPlan) -> None:
        """Remove this grant's IAM binds. Idempotent if none exist."""
        ...

    def drop_view(self, plan: GrantPlan) -> None:
        """Drop ``G_<id>``. Must succeed if the view does not exist."""
        ...

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
    """GoogleSQL string literal. Escape backslash first, then quote as \\'."""
    out: list[str] = []
    for ch in value:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "'":
            out.append("\\'")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\v":
            out.append("\\v")
        elif ch == "\u2028":
            out.append("\\u2028")
        elif ch == "\u2029":
            out.append("\\u2029")
        elif ch == "\u0085":
            out.append("\\u0085")
        elif o < 32 or o == 127:
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    return "'" + "".join(out) + "'"


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


def _parse_principal(raw: str) -> str:
    principal = raw.strip()
    if not principal:
        raise GrantError("google principal is required")
    _reject_controls("google principal", principal)
    lowered = principal.lower()
    if lowered in _REFUSED_PRINCIPALS or lowered.startswith("domain:"):
        raise GrantError(f"refused google principal {principal!r}")
    if not any(principal.startswith(p) for p in _PRINCIPAL_PREFIXES):
        raise GrantError("google principal must be user:, serviceAccount:, or group:")
    rest = principal.split(":", 1)[1]
    if not _EMAIL_RE.fullmatch(rest):
        raise GrantError("google principal email is invalid")
    return principal


def _col_expr(col: str, mask: str, hash_scope: str, *, project: str) -> str:
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
        fn = f"{q_project(project)}.{q(STATE_DATASET)}.{q(HASH_UDF)}"
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
    source_project: str | None = None,
) -> str:
    """SELECT for G_<id>. Calls project.datagrant.hash_hmac; never embeds key bytes."""
    cols = ", ".join(_col_expr(c, masks[c], hash_scope, project=project) for c in req.columns)
    ds, table = _split_table(req.table, source_dataset)
    from_project = project if source_project is None else source_project
    from_tbl = f"{q_project(from_project)}.{q(ds)}.{q(table)}"
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
    source_project: str | None = None,
    location: str | None = None,
    grant_id: str | None = None,
    now: datetime | None = None,
    approvers: Sequence[str] = (),
    hash_key: HashKey | None = None,
    requester_identity: Mapping[str, Any] | None = None,
    approver_identities: Sequence[Mapping[str, Any]] | None = None,
) -> GrantPlan:
    """Pure plan, including IAM condition titles and resource.name for G_<id>."""
    if not decision.allowed:
        raise GrantError("cannot build a grant for a denied decision")
    if decision.approval == "two-person" and not approvers:
        raise GrantError("two-person approval: the grant needs an approver")
    principal = _parse_principal(principal)
    _reject_controls("purpose", req.purpose)
    gid = grant_id or secrets.token_hex(6)
    if not _GRANT_ID_RE.fullmatch(gid):
        raise GrantError("grant id must be 12 lowercase hex characters")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise GrantError("now must be timezone-aware")
    expires = now + req.duration
    q_project(project)
    from_project = project if source_project is None else source_project
    ds, _table = _split_table(req.table, source_dataset)
    needs_hash = any(decision.masks[c] == "hash" for c in req.columns)
    if needs_hash and hash_key is None:
        raise GrantError("hash masking requires a hash key file (see keys.hash_key_path)")
    scope = decision.hash_scope or req.dataset
    view_sql = view_select_sql(
        req,
        decision.masks,
        project=project,
        source_dataset=ds,
        hash_scope=scope,
        source_project=from_project,
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
        f"{from_project}.{ds}",
        req.table,
        principal,
        expires,
        location,
        facts,
        hash_key if needs_hash else None,
    )


def reverse_drop(client: GrantClient, plan: GrantPlan, *, unbind: bool = False) -> None:
    """Unbind (if IAM was attempted), drop the view, always mark_failed.

    Each step is try/finally so one failure cannot skip the next. Never
    de-authorize the standing source dataset. ``unbind_iam`` and ``drop_view``
    must succeed if the object does not exist.
    """
    parts: list[str] = []
    try:
        if unbind:
            try:
                client.unbind_iam(plan)
            except Exception as exc:  # noqa: BLE001 - drop_view still runs
                parts.append(f"unbind_iam failed ({exc})")
    finally:
        try:
            try:
                client.drop_view(plan)
            except Exception as exc:  # noqa: BLE001 - mark_failed still runs
                parts.append(f"drop_view failed ({exc})")
        finally:
            try:
                client.mark_failed(plan)
            except Exception as exc:  # noqa: BLE001 - still report earlier errors
                parts.append(f"mark_failed failed ({exc})")
    if parts:
        raise GrantError(f"grant {plan.grant_id}: {'; '.join(parts)}")


def rfc3339(ts: datetime) -> str:
    return ts.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def view_resource_name(project: str, grant_id: str) -> str:
    return f"projects/{project}/datasets/{VIEW_DATASET}/tables/G_{grant_id}"


def grantee_role(project: str) -> str:
    return f"projects/{project}/roles/{GRANTEE_ROLE_ID}"


def condition_title(grant_id: str) -> str:
    return f"G_{grant_id}"


def dataset_condition_expr(plan: GrantPlan) -> str:
    name = view_resource_name(plan.project, plan.grant_id)
    return (
        f'resource.type == "{TABLE_RESOURCE_TYPE}" && '
        f'resource.service == "{TABLE_RESOURCE_SERVICE}" && '
        f'resource.name == "{name}" && '
        f'request.time < timestamp("{rfc3339(plan.expires_at)}")'
    )


def job_user_condition_expr(plan: GrantPlan) -> str:
    return f'request.time < timestamp("{rfc3339(plan.expires_at)}")'


def dataset_binding(plan: GrantPlan) -> dict[str, Any]:
    return {
        "role": grantee_role(plan.project),
        "members": [plan.principal],
        "condition": {
            "title": condition_title(plan.grant_id),
            "expression": dataset_condition_expr(plan),
        },
    }


def job_user_binding(plan: GrantPlan) -> dict[str, Any]:
    return {
        "role": JOB_USER_ROLE,
        "members": [plan.principal],
        "condition": {
            "title": condition_title(plan.grant_id),
            "expression": job_user_condition_expr(plan),
        },
    }


def _binding_title(binding: Mapping[str, Any]) -> str | None:
    cond = binding.get("condition")
    if not isinstance(cond, dict):
        return None
    title = cond.get("title")
    return title if isinstance(title, str) else None


def _binding_expr(binding: Mapping[str, Any]) -> str | None:
    cond = binding.get("condition")
    if not isinstance(cond, dict):
        return None
    expr = cond.get("expression")
    return expr if isinstance(expr, str) else None


def _ours(existing: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    """True only when role, condition title, and expression all match."""
    return (
        existing.get("role") == expected.get("role")
        and _binding_title(existing) == _binding_title(expected)
        and _binding_expr(existing) == _binding_expr(expected)
    )


def _upsert_binding(policy: IamPolicy, binding: dict[str, Any]) -> bool:
    title = _binding_title(binding)
    principal = binding["members"][0]
    for existing in policy.bindings:
        if _binding_title(existing) != title:
            continue
        if not _ours(existing, binding):
            raise GrantError(f"IAM condition title {title} already in use")
        members = existing.get("members")
        if not isinstance(members, list):
            raise GrantError(f"IAM condition title {title} already in use")
        if principal in members:
            return False
        members.append(principal)
        return True
    policy.bindings.append(binding)
    return True


def _remove_grant_bindings(policy: IamPolicy, expected: Mapping[str, Any]) -> bool:
    """Remove plan.principal from the matching binding; drop it if empty."""
    principal = expected["members"][0]
    title = _binding_title(expected)
    changed = False
    keep: list[dict[str, Any]] = []
    for existing in policy.bindings:
        if _binding_title(existing) != title or not _ours(existing, expected):
            keep.append(existing)
            continue
        members = existing.get("members")
        if not isinstance(members, list) or principal not in members:
            keep.append(existing)
            continue
        changed = True
        remaining = [m for m in members if m != principal]
        if remaining:
            updated = dict(existing)
            updated["members"] = remaining
            keep.append(updated)
    if changed:
        policy.bindings[:] = keep
    return changed


def _conditional_cap_hit(msg: str) -> bool:
    lower = msg.lower()
    if "condition" not in lower:
        return False
    cap = any(w in lower for w in ("limit", "exceed", "too many", "quota", "maximum"))
    who = any(w in lower for w in ("principal", "member", "identity"))
    return cap and who


def _rmw(
    getter: Any,
    setter: Any,
    edit: Any,
    *,
    skip_unchanged: bool = False,
) -> None:
    last: Exception | None = None
    for _attempt in range(ETAG_MAX_TRIES):
        policy = getter(access_policy_version=ACCESS_POLICY_VERSION)
        if not getattr(policy, "etag", None):
            raise GrantError("IAM policy etag missing")
        changed = edit(policy)
        policy.version = ACCESS_POLICY_VERSION
        if skip_unchanged and not changed:
            return
        try:
            setter(policy, access_policy_version=ACCESS_POLICY_VERSION)
            return
        except ConflictError as exc:
            last = exc
            continue
        except Exception as exc:
            if _conditional_cap_hit(str(exc)):
                raise GrantError(
                    "Google IAM per-principal conditional-binding cap was hit"
                ) from exc
            raise
    raise GrantError(f"IAM etag conflict after {ETAG_MAX_TRIES} attempts") from last


def apply_bind(client: GrantClient, plan: GrantPlan) -> None:
    """Add this grant's dataset bind and project jobUser bind (etag RMW)."""
    try:
        _rmw(
            lambda **kw: client.get_dataset_iam(plan.project, VIEW_DATASET, **kw),
            lambda policy, **kw: client.set_dataset_iam(plan.project, VIEW_DATASET, policy, **kw),
            lambda policy: _upsert_binding(policy, dataset_binding(plan)),
        )
        _rmw(
            lambda **kw: client.get_project_iam(plan.project, **kw),
            lambda policy, **kw: client.set_project_iam(plan.project, policy, **kw),
            lambda policy: _upsert_binding(policy, job_user_binding(plan)),
        )
    except GrantError as exc:
        prefix = f"grant {plan.grant_id}: "
        if str(exc).startswith(prefix):
            raise
        raise GrantError(prefix + str(exc)) from exc


def apply_unbind(client: GrantClient, plan: GrantPlan) -> None:
    """Remove this grant's principal from matching bindings. Idempotent.

    A binding is ours only when role, title, and expression match. Project
    jobUser and dataset unbinds both run even if one fails.
    """
    parts: list[str] = []
    try:
        try:
            _rmw(
                lambda **kw: client.get_project_iam(plan.project, **kw),
                lambda policy, **kw: client.set_project_iam(plan.project, policy, **kw),
                lambda policy: _remove_grant_bindings(policy, job_user_binding(plan)),
                skip_unchanged=True,
            )
        except Exception as exc:  # noqa: BLE001 - dataset unbind still runs
            parts.append(f"project jobUser unbind failed ({_strip_grant_prefix(plan, str(exc))})")
    finally:
        try:
            _rmw(
                lambda **kw: client.get_dataset_iam(plan.project, VIEW_DATASET, **kw),
                lambda policy, **kw: client.set_dataset_iam(
                    plan.project, VIEW_DATASET, policy, **kw
                ),
                lambda policy: _remove_grant_bindings(policy, dataset_binding(plan)),
                skip_unchanged=True,
            )
        except Exception as exc:  # noqa: BLE001 - still report project error
            parts.append(f"dataset unbind failed ({_strip_grant_prefix(plan, str(exc))})")
    if parts:
        raise GrantError(f"grant {plan.grant_id}: {'; '.join(parts)}")


def _strip_grant_prefix(plan: GrantPlan, msg: str) -> str:
    return msg.removeprefix(f"grant {plan.grant_id}: ")


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
    """Fail-safe apply. IAM last: dataset bind + project jobUser, etag RMW.

    Cleanup calls ``drop_view`` at most once. ``mark_failed`` always runs.
    A post-issued failure still writes ``revoked`` if cleanup fails.
    """
    if plan.facts is not None and plan.facts.approval == "two-person" and not plan.facts.approvers:
        raise GrantError("two-person approval: the grant needs an approver")
    created = False
    issued = False
    iam_attempted = False
    revoked_reason = "apply_failed"
    try:
        client.insert_issuing(plan)
        created = True
        client.create_view(plan)
        client.authorize_views_dataset_if_missing(plan)
        if client.update_names(plan) != 1:
            raise GrantError(f"grant {plan.grant_id}: not issuing at row update; view dropped")
        if receipts is None:
            raise GrantError(f"grant {plan.grant_id}: issued receipt is required before IAM")
        if plan.facts is None:
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
        except Exception as exc:
            raise GrantError(
                f"grant {plan.grant_id}: receipt not written ({exc}); view dropped"
            ) from exc
        if client.claim_enabling(plan) != 1:
            revoked_reason = "lost_issuing"
            raise GrantError(f"grant {plan.grant_id}: not issuing at IAM; view dropped")
        iam_attempted = True
        try:
            client.bind_iam(plan)
        except GrantError:
            revoked_reason = "iam_failed"
            raise
        except BaseException as exc:
            revoked_reason = "iam_failed"
            if not isinstance(exc, Exception):
                raise
            raise GrantError(f"grant {plan.grant_id}: IAM failed ({exc}); view dropped") from exc
        if client.claim_active(plan) != 1:
            revoked_reason = "lost_enabling"
            raise GrantError(f"grant {plan.grant_id}: not enabling after IAM; view dropped")
    except BaseException as original:
        # GrantError from a client call is included: cleanup still runs.
        cleanup_exc: Exception | None = None
        if created:
            try:
                reverse_drop(client, plan, unbind=iam_attempted)
            except Exception as exc:  # noqa: BLE001 - keep original; name both
                cleanup_exc = exc
            if issued:
                append_revoked(plan, receipts, reason=revoked_reason)
        if not isinstance(original, Exception):
            # Bare `raise` would re-raise cleanup_exc if reverse_drop failed.
            raise original  # noqa: TRY201
        if cleanup_exc is not None:
            orig = _strip_grant_prefix(plan, str(original))
            clean = _strip_grant_prefix(plan, str(cleanup_exc))
            raise GrantError(
                f"grant {plan.grant_id}: {orig}; cleanup failed ({clean})"
            ) from original
        if isinstance(original, GrantError):
            raise
        raise GrantError(f"grant {plan.grant_id} failed: {original}") from original
