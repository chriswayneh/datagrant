"""Policy file loading, validation, and request evaluation (unit U1).

Pure logic: no database or network access. Deny by default.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from datagrant.oidc import (
    ALLOWED_ALGS,
    DEFAULT_ALGS,
    DEFAULT_CLOCK_SKEW,
    DEFAULT_JWKS_CACHE_TTL,
    DEFAULT_MAX_TOKEN_AGE,
    IDENTITY_MODES,
    IdentityConfig,
    allow_insecure_localhost,
    normalize_principal,
    validate_oidc_url,
)
from datagrant.rowfilter import RowFilterError, parse_row_filter

MASK_TYPES = frozenset({"passthrough", "redact", "hash", "partial", "null"})
APPROVAL_MODES = frozenset({"auto", "two-person"})
_DURATION_RE = re.compile(r"^(\d{1,6})([mhd])$")
_SMALL_DURATION_RE = re.compile(r"^(\d{1,6})([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MEMBER_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
MAX_POLICY_BYTES = 1_000_000


class PolicyError(ValueError):
    """Raised when a policy file is missing, malformed, or invalid."""


def parse_duration(value: object, where: str = "duration") -> timedelta:
    """Parse '30m', '4h', or '2d' into a positive timedelta."""
    if not isinstance(value, str):
        raise PolicyError(f"{where}: expected a string like '4h', got {type(value).__name__}")
    m = _DURATION_RE.fullmatch(value.strip())
    if not m or int(m.group(1)) == 0:
        raise PolicyError(f"{where}: invalid duration {value!r} (use e.g. '30m', '4h', '1d')")
    try:
        return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    except OverflowError as exc:  # pragma: no cover - bounded by regex; defensive
        raise PolicyError(f"{where}: duration {value!r} is too large") from exc


@dataclass(frozen=True)
class TableRule:
    name: str  # schema.table
    allowed_groups: frozenset[str]
    columns: dict[str, str]  # column -> mask type
    row_filters: tuple[str, ...]
    require_row_filter: bool
    max_duration: timedelta
    filter_columns: frozenset[str] = frozenset()
    max_columns: int | None = None


@dataclass(frozen=True)
class Dataset:
    name: str
    database: str
    tables: dict[str, TableRule]
    hash_scope: str = ""
    max_concurrent_grants: int | None = None

    def __post_init__(self) -> None:
        if not self.hash_scope:
            object.__setattr__(self, "hash_scope", self.name)


@dataclass(frozen=True)
class Policy:
    version: int
    approval: str
    max_duration: timedelta
    groups: dict[str, frozenset[str]]
    datasets: dict[str, Dataset]
    sha256: str
    approver_groups: frozenset[str] = frozenset()
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    pending_ttl: timedelta | None = None
    max_concurrent_grants: int | None = None
    approvals_required: int = 1

    def concurrent_grant_cap(self, dataset: str) -> int | None:
        """Minimum of the policy-wide and dataset caps that are set, or None."""
        ds = self.datasets[dataset]
        caps = [c for c in (self.max_concurrent_grants, ds.max_concurrent_grants) if c is not None]
        return min(caps) if caps else None

    def can_approve(
        self, approver: str, requester: str, extra_groups: frozenset[str] = frozenset()
    ) -> list[str]:
        """Reasons the approver may not approve this requester (empty list = allowed)."""
        reasons = []
        if approver == requester or approver.casefold() == requester.casefold():
            reasons.append("approver must be a different person than the requester")
        if not (self.groups_of(approver) | extra_groups) & self.approver_groups:
            reasons.append(f"{approver!r} is not in an approver group")
        return reasons

    def groups_of(self, requester: str) -> frozenset[str]:
        norm = normalize_principal(requester)
        return frozenset(
            g for g, members in self.groups.items() if norm in members or requester in members
        )


@dataclass(frozen=True)
class Request:
    requester: str
    dataset: str
    table: str
    columns: tuple[str, ...]
    duration: timedelta
    purpose: str
    row_filter: str | None = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reasons: tuple[str, ...]
    approval: str
    policy_sha256: str
    masks: dict[str, str] = field(default_factory=dict)
    policy_version: int = 1
    hash_scope: str | None = None


def _req(d: dict[str, Any], key: str, typ: type, where: str) -> Any:
    if key not in d:
        raise PolicyError(f"{where}: missing required key '{key}'")
    val = d[key]
    if typ is int and isinstance(val, bool) or not isinstance(val, typ):
        raise PolicyError(f"{where}.{key}: expected {typ.__name__}")
    return val


def _check_keys(d: dict[str, Any], allowed: set[str], where: str) -> None:
    extra = set(d) - allowed
    if extra:
        raise PolicyError(f"{where}: unknown key(s) {sorted(extra)}")


def _positive_int(val: object, where: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or val < 1:
        raise PolicyError(f"{where}: expected a positive integer")
    return val


def _str_list(val: object, where: str) -> list[str]:
    if not isinstance(val, list) or not all(isinstance(x, str) and x for x in val):
        raise PolicyError(f"{where}: expected a list of non-empty strings")
    return val


def _parse_table(raw: object, where: str, cap: timedelta, groups: set[str]) -> TableRule:
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(
        raw,
        {
            "name",
            "allowed_groups",
            "columns",
            "filter_columns",
            "row_filters",
            "require_row_filter",
            "max_duration",
            "max_columns",
        },
        where,
    )
    name = _req(raw, "name", str, where)
    parts = name.split(".")
    if len(parts) != 2 or not all(_IDENT_RE.fullmatch(p) for p in parts):
        raise PolicyError(f"{where}.name: expected 'schema.table' identifiers, got {name!r}")
    allowed = _str_list(_req(raw, "allowed_groups", list, where), f"{where}.allowed_groups")
    for g in allowed:
        if g not in groups:
            raise PolicyError(f"{where}.allowed_groups: unknown group {g!r}")
    cols = _req(raw, "columns", dict, where)
    if not cols:
        raise PolicyError(f"{where}.columns: must list at least one column")
    for col, mask in cols.items():
        if not isinstance(col, str) or not _IDENT_RE.fullmatch(col):
            raise PolicyError(f"{where}.columns: invalid column name {col!r}")
        if not isinstance(mask, str) or mask not in MASK_TYPES:
            raise PolicyError(
                f"{where}.columns.{col}: unknown mask {mask!r} (one of {sorted(MASK_TYPES)})"
            )
    fcols = _str_list(raw.get("filter_columns", []), f"{where}.filter_columns")
    for col in fcols:
        if not _IDENT_RE.fullmatch(col):
            raise PolicyError(f"{where}.filter_columns: invalid column name {col!r}")
        if col in cols:
            raise PolicyError(
                f"{where}.filter_columns: {col!r} is also in columns (list it in one place)"
            )
    if len(set(fcols)) != len(fcols):
        raise PolicyError(f"{where}.filter_columns: duplicate column names")
    filters = _str_list(raw.get("row_filters", []), f"{where}.row_filters")
    for k, f in enumerate(filters):
        try:
            _, used = parse_row_filter(f)
        except RowFilterError as exc:
            raise PolicyError(f"{where}.row_filters[{k}]: {exc}") from None
        outside = sorted(used - set(cols) - set(fcols))
        if outside:
            raise PolicyError(
                f"{where}.row_filters[{k}]: references columns not listed in columns"
                f" or filter_columns: {outside}"
            )
    if fcols and not filters:
        raise PolicyError(f"{where}: filter_columns is set but no row_filters are listed")
    unused = sorted(set(fcols) - {c for f in filters for c in parse_row_filter(f)[1]})
    if unused:
        raise PolicyError(f"{where}.filter_columns: not used by any row filter: {unused}")
    require = raw.get("require_row_filter", False)
    if not isinstance(require, bool):
        raise PolicyError(f"{where}.require_row_filter: expected true/false")
    if require and not filters:
        raise PolicyError(f"{where}: require_row_filter is true but no row_filters are listed")
    max_d = (
        parse_duration(raw["max_duration"], f"{where}.max_duration")
        if ("max_duration" in raw)
        else cap
    )
    if max_d > cap:
        raise PolicyError(f"{where}.max_duration exceeds the policy-wide max_duration")
    max_cols: int | None = None
    if "max_columns" in raw:
        max_cols = _positive_int(raw["max_columns"], f"{where}.max_columns")
        if max_cols > len(cols):
            raise PolicyError(
                f"{where}.max_columns cannot exceed the number of columns ({len(cols)})"
            )
    return TableRule(
        name,
        frozenset(allowed),
        dict(cols),
        tuple(filters),
        require,
        max_d,
        frozenset(fcols),
        max_cols,
    )


def _parse_seconds_duration(
    value: object, where: str, *, low: timedelta, high: timedelta
) -> timedelta:
    if not isinstance(value, str):
        raise PolicyError(f"{where}: expected a duration string like '60s' or '5m'")
    m = _SMALL_DURATION_RE.fullmatch(value.strip())
    if not m:
        raise PolicyError(f"{where}: invalid duration {value!r} (use e.g. '0s', '60s', '5m', '1h')")
    td = timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    if td < low or td > high:
        raise PolicyError(f"{where}: duration {value!r} out of range ({low}..{high})")
    return td


def _parse_identity(
    raw: object, groups: set[str], env: Mapping[str, str] | None = None
) -> IdentityConfig:
    if raw is None:
        return IdentityConfig()
    where = "policy.identity"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(
        raw,
        {
            "mode",
            "issuer",
            "audience",
            "algorithms",
            "username_claim",
            "groups_claim",
            "allowed_groups",
            "group_map",
            "max_token_age",
            "clock_skew",
            "jwks_cache_ttl",
        },
        where,
    )
    mode = raw.get("mode", "local")
    if not isinstance(mode, str) or mode not in IDENTITY_MODES:
        raise PolicyError(f"{where}.mode: must be one of {sorted(IDENTITY_MODES)}")
    if mode == "local":
        extra = sorted(set(raw) - {"mode"})
        if extra:
            raise PolicyError(f"{where}: OIDC keys {extra} are not allowed when mode is 'local'")
        return IdentityConfig(mode="local")
    issuer = _req(raw, "issuer", str, where)
    try:
        validate_oidc_url(
            issuer, f"{where}.issuer", allow_localhost_http=allow_insecure_localhost(env)
        )
    except ValueError as exc:
        raise PolicyError(str(exc)) from None
    raw_aud = raw.get("audience")
    aud: tuple[str, ...]
    if isinstance(raw_aud, str) and raw_aud:
        aud = (raw_aud,)
    elif isinstance(raw_aud, list) and raw_aud:
        aud = tuple(_str_list(raw_aud, f"{where}.audience"))
    else:
        raise PolicyError(f"{where}.audience: expected a non-empty string or list of strings")
    algs = (
        tuple(_str_list(raw["algorithms"], f"{where}.algorithms"))
        if "algorithms" in raw
        else DEFAULT_ALGS
    )
    if not algs or any(a not in ALLOWED_ALGS for a in algs):
        raise PolicyError(
            f"{where}.algorithms: must be a non-empty subset of {sorted(ALLOWED_ALGS)}"
        )
    uclaim = raw.get("username_claim", "sub")
    if not isinstance(uclaim, str) or not _NAME_RE.fullmatch(uclaim):
        raise PolicyError(f"{where}.username_claim: invalid claim name {uclaim!r}")
    gclaim = raw.get("groups_claim")
    if gclaim is not None and (not isinstance(gclaim, str) or not _NAME_RE.fullmatch(gclaim)):
        raise PolicyError(f"{where}.groups_claim: invalid claim name {gclaim!r}")
    allowed_g = frozenset(_str_list(raw.get("allowed_groups", []), f"{where}.allowed_groups"))
    raw_map = raw.get("group_map", {})
    if not isinstance(raw_map, dict):
        raise PolicyError(f"{where}.group_map: expected a mapping")
    gmap: dict[str, str] = {}
    for k, v in raw_map.items():
        if not isinstance(k, str) or not k or not isinstance(v, str) or not v:
            raise PolicyError(f"{where}.group_map: keys and values must be non-empty strings")
        if v not in groups:
            raise PolicyError(f"{where}.group_map: target group {v!r} is not in policy.groups")
        gmap[k] = v
    if (allowed_g or gmap) and gclaim is None:
        raise PolicyError(
            f"{where}: groups_claim is required when allowed_groups or group_map is set"
        )
    max_age = (
        _parse_seconds_duration(
            raw["max_token_age"],
            f"{where}.max_token_age",
            low=timedelta(minutes=1),
            high=timedelta(hours=24),
        )
        if "max_token_age" in raw
        else DEFAULT_MAX_TOKEN_AGE
    )
    skew = (
        _parse_seconds_duration(
            raw["clock_skew"],
            f"{where}.clock_skew",
            low=timedelta(seconds=0),
            high=timedelta(minutes=5),
        )
        if "clock_skew" in raw
        else DEFAULT_CLOCK_SKEW
    )
    ttl = (
        _parse_seconds_duration(
            raw["jwks_cache_ttl"],
            f"{where}.jwks_cache_ttl",
            low=timedelta(seconds=0),
            high=timedelta(hours=24),
        )
        if "jwks_cache_ttl" in raw
        else DEFAULT_JWKS_CACHE_TTL
    )
    return IdentityConfig(
        mode="oidc",
        issuer=issuer,
        audience=aud,
        algorithms=frozenset(algs),
        username_claim=uclaim,
        groups_claim=gclaim,
        allowed_groups=allowed_g,
        group_map=gmap,
        max_token_age=max_age,
        clock_skew=skew,
        jwks_cache_ttl=ttl,
    )


def parse_policy(data: object, sha256: str = "", *, env: Mapping[str, str] | None = None) -> Policy:
    """Validate a decoded policy document and build a Policy."""
    if not isinstance(data, dict):
        raise PolicyError("policy: top level must be a mapping")
    _check_keys(
        data,
        {
            "version",
            "approval",
            "approvers",
            "max_duration",
            "groups",
            "datasets",
            "identity",
            "pending_ttl",
            "max_concurrent_grants",
            "approvals_required",
        },
        "policy",
    )
    version = _req(data, "version", int, "policy")
    if version != 1:
        raise PolicyError(f"policy.version: unsupported version {version} (expected 1)")
    approval = data.get("approval", "auto")
    if approval not in APPROVAL_MODES:
        raise PolicyError(f"policy.approval: must be one of {sorted(APPROVAL_MODES)}")
    cap = parse_duration(_req(data, "max_duration", str, "policy"), "policy.max_duration")
    groups: dict[str, frozenset[str]] = {}
    seen_spellings: dict[str, str] = {}
    for g, members in _req(data, "groups", dict, "policy").items():
        if not isinstance(g, str) or not _NAME_RE.fullmatch(g):
            raise PolicyError(f"policy.groups: invalid group name {g!r}")
        raw_members = _str_list(members, f"policy.groups.{g}")
        norm_set: set[str] = set()
        for m in raw_members:
            if not _MEMBER_RE.fullmatch(m):
                raise PolicyError(
                    f"policy.groups.{g}: invalid member name {m!r} (expected 1..256 printable ASCII chars)"
                )
            norm = normalize_principal(m)
            if norm in norm_set:
                raise PolicyError(
                    f"policy.groups.{g}: duplicate member {m!r} (normalized to {norm!r})"
                )
            prev_raw = seen_spellings.get(norm)
            if prev_raw is not None and prev_raw != m:
                raise PolicyError(
                    f"policy.groups.{g}: conflicting member spellings {prev_raw!r} and {m!r}"
                    f" both normalize to {norm!r}"
                )
            seen_spellings[norm] = m
            norm_set.add(norm)
        groups[g] = frozenset(norm_set)
    datasets: dict[str, Dataset] = {}
    raw_ds = _req(data, "datasets", list, "policy")
    if not raw_ds:
        raise PolicyError("policy.datasets: must define at least one dataset")
    for i, ds in enumerate(raw_ds):
        where = f"policy.datasets[{i}]"
        if not isinstance(ds, dict):
            raise PolicyError(f"{where}: expected a mapping")
        _check_keys(
            ds, {"name", "database", "tables", "hash_scope", "max_concurrent_grants"}, where
        )
        name = _req(ds, "name", str, where)
        if not _NAME_RE.fullmatch(name) or name in datasets:
            raise PolicyError(f"{where}.name: invalid or duplicate dataset name {name!r}")
        db = _req(ds, "database", str, where)
        if not _IDENT_RE.fullmatch(db):
            raise PolicyError(f"{where}.database: invalid database name {db!r}")
        scope = ds.get("hash_scope", name)
        if not isinstance(scope, str) or not _NAME_RE.fullmatch(scope):
            raise PolicyError(f"{where}.hash_scope: invalid hash scope {scope!r}")
        tables: dict[str, TableRule] = {}
        for j, t in enumerate(_req(ds, "tables", list, where)):
            rule = _parse_table(t, f"{where}.tables[{j}]", cap, set(groups))
            if rule.name in tables:
                raise PolicyError(f"{where}.tables[{j}]: duplicate table {rule.name!r}")
            tables[rule.name] = rule
        if not tables:
            raise PolicyError(f"{where}.tables: must define at least one table")
        ds_cap = (
            _positive_int(ds["max_concurrent_grants"], f"{where}.max_concurrent_grants")
            if "max_concurrent_grants" in ds
            else None
        )
        datasets[name] = Dataset(name, db, tables, scope, ds_cap)
    approvers = frozenset(_str_list(data.get("approvers", []), "policy.approvers"))
    unknown = approvers - set(groups)
    if unknown:
        raise PolicyError(f"policy.approvers: unknown groups {sorted(unknown)}")
    if approval == "two-person" and not approvers:
        raise PolicyError("policy.approvers: two-person approval needs at least one approver group")
    ident = _parse_identity(data.get("identity"), set(groups), env=env)
    pending_ttl: timedelta | None = None
    if "pending_ttl" in data:
        pending_ttl = parse_duration(data["pending_ttl"], "policy.pending_ttl")
        if pending_ttl < timedelta(minutes=1) or pending_ttl > timedelta(days=7):
            raise PolicyError(
                f"policy.pending_ttl: duration {data['pending_ttl']!r} out of range (1m..7d)"
            )
    max_cg = (
        _positive_int(data["max_concurrent_grants"], "policy.max_concurrent_grants")
        if "max_concurrent_grants" in data
        else None
    )
    approvals_required = 1
    if "approvals_required" in data:
        if approval != "two-person":
            raise PolicyError("policy.approvals_required: only valid when approval is two-person")
        raw_n = data["approvals_required"]
        if isinstance(raw_n, bool) or not isinstance(raw_n, int):
            raise PolicyError("policy.approvals_required: expected an integer")
        if raw_n < 1 or raw_n > 8:
            raise PolicyError("policy.approvals_required: must be an integer from 1 to 8")
        approvals_required = raw_n
    return Policy(
        version,
        approval,
        cap,
        groups,
        datasets,
        sha256,
        approvers,
        ident,
        pending_ttl,
        max_cg,
        approvals_required,
    )


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects anchors/aliases and duplicate mapping keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise PolicyError(f"YAML anchors/aliases are not allowed ({event.start_mark})")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                dup = key in seen
            except TypeError:
                raise PolicyError(f"unhashable YAML mapping key ({key_node.start_mark})") from None
            if dup:
                raise PolicyError(f"duplicate YAML key {key!r} ({key_node.start_mark})")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_policy(path: str | Path) -> Policy:
    """Read, size-check, safely parse, and validate a YAML policy file."""
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"cannot read policy file {p}: not a regular file")
    try:
        with p.open("rb") as fh:
            raw = fh.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {p}: {exc.strerror}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy file {p} is larger than {MAX_POLICY_BYTES} bytes")
    try:
        data = yaml.load(raw, Loader=_StrictLoader)  # nosec B506
        return parse_policy(data, hashlib.sha256(raw).hexdigest())
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {p} is not valid YAML: {exc}") from exc
    except RecursionError:
        raise PolicyError(f"policy file {p} is nested too deeply") from None


def evaluate(
    policy: Policy, req: Request, *, extra_groups: frozenset[str] = frozenset()
) -> Decision:
    """Return allow/deny for a request. Deny by default; collect every reason."""
    reasons: list[str] = []

    def deny(*extra: str) -> Decision:
        return Decision(
            False, tuple(reasons) + extra, policy.approval, policy.sha256, {}, policy.version
        )

    if not req.purpose.strip():
        reasons.append("purpose is required")
    if not req.columns:
        reasons.append("at least one column must be requested")
    ds = policy.datasets.get(req.dataset)
    if ds is None:
        return deny(f"dataset {req.dataset!r} is not in policy")
    rule = ds.tables.get(req.table)
    if rule is None:
        return deny(f"table {req.table!r} is not in dataset {req.dataset!r}")
    if not (policy.groups_of(req.requester) | extra_groups) & rule.allowed_groups:
        reasons.append(f"requester {req.requester!r} is not in an allowed group for {rule.name}")
    bad = [c for c in req.columns if c not in rule.columns]
    if bad:
        reasons.append(f"columns not allowed: {', '.join(sorted(set(bad)))}")
    if len(set(req.columns)) != len(req.columns):
        reasons.append("duplicate columns requested")
    nuniq = len(set(req.columns))
    if rule.max_columns is not None and nuniq > rule.max_columns:
        reasons.append(f"request has {nuniq} columns (max_columns is {rule.max_columns})")
    if req.duration <= timedelta(0):
        reasons.append("duration must be positive")
    elif req.duration > rule.max_duration:
        reasons.append(f"duration {req.duration} exceeds max {rule.max_duration}")
    if req.row_filter is None:
        if rule.require_row_filter:
            reasons.append(f"a row filter is required; allowed: {list(rule.row_filters)}")
    elif req.row_filter not in rule.row_filters:
        reasons.append("row filter is not one of the policy's allowed filters")
    if reasons:
        return deny()
    masks = {c: rule.columns[c] for c in req.columns}
    return Decision(
        True,
        ("allowed by policy",),
        policy.approval,
        policy.sha256,
        masks,
        policy.version,
        ds.hash_scope,
    )
