"""Access-review evidence from an authenticated receipt chain."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from datagrant import receipt

_FIELDS = (
    "seq", "event_at", "event", "grant_id", "requester", "dataset", "table",
    "starts_at", "expires_at", "policy_sha256", "approval",
)
_NOTE = (
    "Receipts record grant lifecycle events, not rows read or current access. "
    "This report supports access reviews; it does not establish PCI DSS compliance."
)


def _project(body: Mapping[str, Any]) -> dict[str, Any]:
    row = {key: body[key] for key in _FIELDS if type(body.get(key)) in (str, int)}
    approvers = body.get("approvers")
    row["approvers"] = (
        [name for name in approvers if isinstance(name, str)] if isinstance(approvers, list) else []
    )
    columns = body.get("columns")
    row["columns"] = (
        [
            {"name": entry["name"], "mask": entry["mask"]}
            for entry in columns
            if isinstance(entry, dict)
            and isinstance(entry.get("name"), str)
            and isinstance(entry.get("mask"), str)
        ]
        if isinstance(columns, list)
        else []
    )
    return row


def build_report(
    log: Path, public_key: Ed25519PublicKey, *, expect_head: str | None = None
) -> dict[str, Any]:
    """Read once and publish no event data unless the entire chain verifies."""
    rows: list[dict[str, Any]] = []
    result = receipt.verify(
        log, public_key, expect_head=expect_head, on_verified=lambda body: rows.append(_project(body))
    )
    if not result.ok:
        location = f" at line {result.line}" if result.line is not None else ""
        raise receipt.ReceiptError(f"receipt verification failed{location}; no report generated")
    return {
        "version": 1,
        "receipt_count": result.count,
        "head_sha256": result.head_sha256,
        "expected_head_checked": expect_head is not None,
        "note": _NOTE,
        "events": rows,
    }


def _cell(value: object) -> str:
    return "".join(
        char if char.isalnum() or char == " " else f"&#{ord(char)};"
        for char in str(value).replace("\r", " ").replace("\n", " ")
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    checked = (
        "Compared with the supplied expected hash."
        if report["expected_head_checked"]
        else "No expected head supplied; deletion of the newest receipts cannot be detected."
    )
    lines = [
        "# DataGrant access evidence",
        "",
        _NOTE,
        "",
        f"Verified receipts: {report['receipt_count']}. Head: `{report['head_sha256']}`.",
        checked,
        "",
        "| Seq | Time (UTC) | Event | Grant | Requester | Approvers | Table | Scope | Expires |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["events"]:
        values = (
            row.get("seq", ""), row.get("event_at", ""), row.get("event", ""),
            row.get("grant_id", ""), row.get("requester", ""), ", ".join(row["approvers"]),
            f"{row.get('dataset', '')}/{row.get('table', '')}",
            ", ".join(f"{col['name']} ({col['mask']})" for col in row["columns"]),
            row.get("expires_at", ""),
        )
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    return "\n".join(lines)
