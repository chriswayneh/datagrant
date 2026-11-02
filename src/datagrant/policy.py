"""Policy file loading, validation, and request evaluation (unit U1).

Pure logic: no database or network access. Deny by default.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

MASK_TYPES = frozenset({"passthrough", "redact", "hash", "partial", "null"})
APPROVAL_MODES = frozenset({"auto", "two-person"})
_DURATION_RE = re.compile(r"^(\d{1,6})([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_POLICY_BYTES = 1_000_000


class PolicyError(ValueError):
    """Raised when a policy file is missing, malformed, or invalid."""


def parse_duration(value: object, where: str = "duration") -> timedelta:
    """Parse '30m', '4h', or '2d' into a positive timedelta."""
    if not isinstance(value, str):
        raise PolicyError(f"{where}: expected a string like '4h', got {type(value).__name__}")
    m = _DURATION_RE.match(value.strip())
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


@dataclass(frozen=True)
class Dataset:
    name: str
    database: str
    tables: dict[str, TableRule]


@dataclass(frozen=True)
class Policy:
    version: int
    approval: str
    max_duration: timedelta
    groups: dict[str, frozenset[str]]
    datasets: dict[str, Dataset]
    sha256: str

    def groups_of(self, requester: str) -> frozenset[str]:
        return frozenset(g for g, members in self.groups.items() if requester in members)


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


def _str_list(val: object, where: str) -> list[str]:
    if not isinstance(val, list) or not all(isinstance(x, str) and x for x in val):
        raise PolicyError(f"{where}: expected a list of non-empty strings")
    return val


def _parse_table(raw: object, where: str, cap: timedelta, groups: set[str]) -> TableRule:
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(
        raw,
        {"name", "allowed_groups", "columns", "row_filters", "require_row_filter", "max_duration"},
        where,
    )
    name = _req(raw, "name", str, where)
    parts = name.split(".")
    if len(parts) != 2 or not all(_IDENT_RE.match(p) for p in parts):
        raise PolicyError(f"{where}.name: expected 'schema.table' identifiers, got {name!r}")
    allowed = _str_list(_req(raw, "allowed_groups", list, where), f"{where}.allowed_groups")
    for g in allowed:
        if g not in groups:
            raise PolicyError(f"{where}.allowed_groups: unknown group {g!r}")
    cols = _req(raw, "columns", dict, where)
    if not cols:
        raise PolicyError(f"{where}.columns: must list at least one column")
    for col, mask in cols.items():
        if not isinstance(col, str) or not _IDENT_RE.match(col):
            raise PolicyError(f"{where}.columns: invalid column name {col!r}")
        if not isinstance(mask, str) or mask not in MASK_TYPES:
            raise PolicyError(
                f"{where}.columns.{col}: unknown mask {mask!r} (one of {sorted(MASK_TYPES)})"
            )
    filters = _str_list(raw.get("row_filters", []), f"{where}.row_filters")
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
    return TableRule(name, frozenset(allowed), dict(cols), tuple(filters), require, max_d)


def parse_policy(data: object, sha256: str = "") -> Policy:
    """Validate a decoded policy document and build a Policy."""
    if not isinstance(data, dict):
        raise PolicyError("policy: top level must be a mapping")
    _check_keys(data, {"version", "approval", "max_duration", "groups", "datasets"}, "policy")
    version = _req(data, "version", int, "policy")
    if version != 1:
        raise PolicyError(f"policy.version: unsupported version {version} (expected 1)")
    approval = data.get("approval", "auto")
    if approval not in APPROVAL_MODES:
        raise PolicyError(f"policy.approval: must be one of {sorted(APPROVAL_MODES)}")
    cap = parse_duration(_req(data, "max_duration", str, "policy"), "policy.max_duration")
    groups: dict[str, frozenset[str]] = {}
    for g, members in _req(data, "groups", dict, "policy").items():
        if not isinstance(g, str) or not _NAME_RE.match(g):
            raise PolicyError(f"policy.groups: invalid group name {g!r}")
        groups[g] = frozenset(_str_list(members, f"policy.groups.{g}"))
    datasets: dict[str, Dataset] = {}
    raw_ds = _req(data, "datasets", list, "policy")
    if not raw_ds:
        raise PolicyError("policy.datasets: must define at least one dataset")
    for i, ds in enumerate(raw_ds):
        where = f"policy.datasets[{i}]"
        if not isinstance(ds, dict):
            raise PolicyError(f"{where}: expected a mapping")
        _check_keys(ds, {"name", "database", "tables"}, where)
        name = _req(ds, "name", str, where)
        if not _NAME_RE.match(name) or name in datasets:
            raise PolicyError(f"{where}.name: invalid or duplicate dataset name {name!r}")
        db = _req(ds, "database", str, where)
        if not _IDENT_RE.match(db):
            raise PolicyError(f"{where}.database: invalid database name {db!r}")
        tables: dict[str, TableRule] = {}
        for j, t in enumerate(_req(ds, "tables", list, where)):
            rule = _parse_table(t, f"{where}.tables[{j}]", cap, set(groups))
            if rule.name in tables:
                raise PolicyError(f"{where}.tables[{j}]: duplicate table {rule.name!r}")
            tables[rule.name] = rule
        if not tables:
            raise PolicyError(f"{where}.tables: must define at least one table")
        datasets[name] = Dataset(name, db, tables)
    return Policy(version, approval, cap, groups, datasets, sha256)


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
        data = yaml.load(raw, Loader=_StrictLoader)  # nosec B506 - _StrictLoader subclasses SafeLoader
        return parse_policy(data, hashlib.sha256(raw).hexdigest())
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {p} is not valid YAML: {exc}") from exc
    except RecursionError:
        raise PolicyError(f"policy file {p} is nested too deeply") from None


def evaluate(policy: Policy, req: Request) -> Decision:
    """Return allow/deny for a request. Deny by default; collect every reason."""
    reasons: list[str] = []

    def deny(*extra: str) -> Decision:
        return Decision(False, tuple(reasons) + extra, policy.approval, policy.sha256)

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
    if not policy.groups_of(req.requester) & rule.allowed_groups:
        reasons.append(f"requester {req.requester!r} is not in an allowed group for {rule.name}")
    bad = [c for c in req.columns if c not in rule.columns]
    if bad:
        reasons.append(f"columns not allowed: {', '.join(sorted(set(bad)))}")
    if len(set(req.columns)) != len(req.columns):
        reasons.append("duplicate columns requested")
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
    return Decision(True, ("allowed by policy",), policy.approval, policy.sha256, masks)
