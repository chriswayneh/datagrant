"""datagrant end-to-end demo against a throwaway Postgres.

Run via `make demo` (Docker) or directly with an existing Postgres:
    DATAGRANT_DEMO_DSN=postgresql://admin:pw@localhost:5432/postgres python scripts/demo.py

The admin role needs CREATEROLE (superuser is simplest for a demo). All data is
synthetic and obviously fake. The demo writes only to schema `dg_demo` plus
datagrant's own state, puts keys and receipts in a temp dir, and removes the
temp dir and demo table on exit.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql

from datagrant.cli import main as cli

STEP = 0
POLICY = """\
# demo policy (synthetic data only)
version: 1
approval: {approval}
approvers: [security]
max_duration: 4h
groups:
  ml-team: [alice]
  security: [carol]
datasets:
  - name: clinic
    database: {database}
    tables:
      - name: dg_demo.patients
        allowed_groups: [ml-team]
        columns:
          patient_id: passthrough
          full_name: redact
          ssn: hash
          phone: partial
          birth_date: "null"
          diagnosis_code: passthrough
        filter_columns: [region]   # rows are filtered on region, but region is never shown
        row_filters: ["region = 'west'"]
        require_row_filter: true
  - name: research               # same table, its own hash key (v0.2.0 hash_scope)
    database: {database}
    hash_scope: research-2026
    tables:
      - name: dg_demo.patients
        allowed_groups: [ml-team]
        columns:
          patient_id: passthrough
          ssn: hash
"""
COLS = "patient_id,full_name,ssn,phone,birth_date,diagnosis_code"
RAW_COLS = "patient_id,full_name,ssn,phone,birth_date,region,diagnosis_code"


def check(ok: bool, what: str) -> None:
    if not ok:
        raise SystemExit(f"DEMO FAILED: {what}")


def q(view: str, cols: str = COLS) -> sql.Composed:
    """SELECT the demo columns from a schema-qualified relation (composed safely)."""
    return sql.SQL("SELECT {} FROM {} ORDER BY 1").format(
        sql.SQL(", ").join(sql.Identifier(c) for c in cols.split(",")),
        sql.Identifier(*view.split(".", 1)),
    )


def step(title: str) -> None:
    global STEP
    STEP += 1
    print(f"\n=== DEMO STEP {STEP}: {title}")


def dg(*argv: str, expect: int = 0) -> dict[str, Any]:
    out: list[str] = []
    code = cli(["--json", *argv], out.append)
    data = json.loads(out[-1]) if out else {}
    shown = {
        k: ("<shown once to the requester>" if k == "password" else v) for k, v in data.items()
    }
    print(f"$ datagrant {' '.join(argv)}\n  exit {code}: {json.dumps(shown, default=str)[:600]}")
    if code != expect:
        raise SystemExit(f"DEMO FAILED: expected exit {expect}, got {code}")
    return data


def seed(admin: psycopg.Connection) -> None:
    rnd = random.Random(1234)  # nosec B311 - deterministic synthetic data, not security
    admin.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    admin.execute("DROP SCHEMA IF EXISTS dg_demo CASCADE")
    admin.execute("CREATE SCHEMA dg_demo")
    admin.execute(
        "CREATE TABLE dg_demo.patients (patient_id int PRIMARY KEY, full_name text, ssn text,"
        " phone text, birth_date date, region text, diagnosis_code text)"
    )
    rows = []
    for i in range(1, 9):
        rows.append(
            (
                i,
                f"Fake Patient {i:03d}",
                f"000-00-{i:04d}",  # 000 area numbers are never issued
                f"555-01{rnd.randint(0, 99):02d}-{rnd.randint(1000, 9999)}",  # 555-01xx: fictional
                f"19{rnd.randint(50, 99)}-0{rnd.randint(1, 9)}-1{rnd.randint(0, 9)}",
                "west" if i % 2 else "east",
                rnd.choice(["Z00.00", "Z01.10", "Z13.89"]),
            )
        )
    with admin.cursor() as cur:
        cur.executemany("INSERT INTO dg_demo.patients VALUES (%s,%s,%s,%s,%s,%s,%s)", rows)


def login(g: dict[str, Any], password: str) -> psycopg.Connection:
    return psycopg.connect(**g["connection"], password=password, autocommit=True)


def show(rows: list[tuple[Any, ...]]) -> None:
    for r in rows:
        print("   ", " | ".join("NULL" if v is None else str(v) for v in r))


def run(dsn: str, work: Path) -> None:
    os.environ.update(
        {
            "DATAGRANT_DSN": dsn,
            "DATAGRANT_SIGNING_KEY": str(work / "keys" / "signing.key"),
            "DATAGRANT_HASH_KEY": str(work / "keys" / "hash.key"),
            "DATAGRANT_RECEIPT_LOG": str(work / "receipts.jsonl"),
        }
    )
    with psycopg.connect(dsn, autocommit=True) as admin:
        database = admin.execute("SELECT current_database()").fetchone()[0]  # type: ignore[index]
        step("seed synthetic fake-PHI table dg_demo.patients")
        seed(admin)
        print("admin (raw) view:")
        show(admin.execute(q("dg_demo.patients", RAW_COLS)).fetchall())
        auto, two = work / "policy-auto.yaml", work / "policy-two-person.yaml"
        auto.write_text(POLICY.format(approval="auto", database=database))
        two.write_text(POLICY.format(approval="two-person", database=database))
        req = (
            "--dataset",
            "clinic",
            "--table",
            "dg_demo.patients",
            "--columns",
            COLS,
            "--row-filter",
            "region = 'west'",
            "--duration",
            "1h",
            "--purpose",
            "demo",
        )

        step("create keys (temp dir) and check the policy")
        dg("keys", "init", "--apply")
        dg("policy", "check", str(auto))
        dg("preflight", "--apply")

        (work / "offhost").mkdir(mode=0o700)  # stands in for storage on another host
        sink = (work / "offhost" / "receipts.jsonl").as_uri()

        step("request as alice: dry run (default) changes nothing")
        d = dg("request", "--policy", str(auto), "--as-user", "alice", *req)
        check("password" not in d and "<redacted>" in d["sql"][0], "dry run leaked a secret")

        step("request --apply: auto-approved by policy")
        g1 = dg("request", "--apply", "--policy", str(auto), "--as-user", "alice", *req)
        grantee = login(g1, g1["password"])
        print("grantee sees (masked, west only; region filters rows but is hidden):")
        masked = grantee.execute(q(g1["view"])).fetchall()
        show(masked)
        check(
            len(masked) == 4 and all(r[1] == "[REDACTED]" and r[4] is None for r in masked),
            "masking/filter wrong",
        )
        try:
            grantee.execute("SELECT * FROM dg_demo.patients")
            raise SystemExit("DEMO FAILED: grantee could read the raw table")
        except psycopg.errors.InsufficientPrivilege:
            print("grantee reading the raw table: permission denied (expected)")
        cols = [
            r[0]
            for r in grantee.execute(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_schema || '.' || table_name = %s",
                (g1["view"],),
            ).fetchall()
        ]
        print(f"view columns: {', '.join(sorted(cols))}")
        check("region" not in cols, "filter column leaked into the view")
        print("DEMO MARKER: masked-rows-ok")

        step("hash_scope: the same SSN hashes differently in another dataset")
        g3 = dg(
            "request",
            "--apply",
            "--policy",
            str(auto),
            "--as-user",
            "alice",
            "--dataset",
            "research",
            "--table",
            "dg_demo.patients",
            "--columns",
            "patient_id,ssn",
            "--duration",
            "1h",
            "--purpose",
            "demo",
        )
        with login(g3, g3["password"]) as c3:
            other = c3.execute(q(g3["view"], "patient_id,ssn")).fetchall()
        h_clinic = {r[0]: r[2] for r in masked}[1]
        h_research = dict(other)[1]
        print(f"patient 1 ssn in clinic:   {h_clinic}")
        print(f"patient 1 ssn in research: {h_research}")
        check(h_clinic != h_research, "hashes matched across datasets")
        dg("revoke", g3["grant_id"], "--apply")
        print("DEMO MARKER: hash-scope-ok")

        step("two-person: pending, self-approval refused, approver approves")
        p = dg("request", "--apply", "--policy", str(two), "--as-user", "alice", *req)
        dg(
            "approve",
            p["request_id"],
            "--apply",
            "--policy",
            str(two),
            "--as-user",
            "alice",
            expect=1,
        )
        g2 = dg("approve", p["request_id"], "--apply", "--policy", str(two), "--as-user", "carol")
        with login(g2, p["password"]) as c2:
            n = c2.execute(
                sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(*g2["view"].split(".", 1)))
            ).fetchone()
        print(f"alice logs in with the password from her request: {n[0] if n else 0} rows")
        print("DEMO MARKER: two-person-ok")

        step("revoke the first grant while its session is open")
        r = dg("revoke", g1["grant_id"], "--apply")
        check(
            r["outcome"] == "revoked" and r["sessions_terminated"] >= 1,
            "revoke did not end the session",
        )
        try:
            grantee.execute("SELECT 1")
            raise SystemExit("DEMO FAILED: session survived revoke")
        except psycopg.OperationalError:
            print("open grantee session was terminated (expected)")
        grantee.close()
        print("DEMO MARKER: revoke-ok")

        step("sweep: fast-forward the second grant's expiry (demo shortcut), then sweep")
        admin.execute(
            "UPDATE datagrant.grants SET expires_at = now() - interval '1 second' WHERE id = %s",
            (g2["grant_id"],),
        )
        dg("sweep")  # dry run shows what would happen
        s = dg("sweep", "--apply")
        check([x["outcome"] for x in s["results"]] == ["revoked"], "sweep did not revoke")
        print("DEMO MARKER: sweep-ok")

        step("verify the signed, hash-chained receipts")
        v = dg("receipts", "verify")
        check(
            v["ok"] and v["count"] == 6,
            "receipts did not verify (expect issued x3, revoked x2, expired)",
        )
        dg("receipts", "verify", "--expect-head", v["head_sha256"])
        print(f"record this head hash outside the host: {v['head_sha256']}")
        print("DEMO MARKER: receipts-ok")

        step("external receipt sink: push the outbox, verify against it, catch truncation")
        p0 = dg("receipts", "push", "--receipt-sink", sink)  # dry run
        check(p0["pending"] == 6, "outbox should hold every receipt")
        dg("receipts", "push", "--apply", "--receipt-sink", sink)
        ok = dg("receipts", "verify", "--sink", sink)
        check(ok["ok"] and ok["undelivered"] == 0, "sink should match the local log")
        log = work / "receipts.jsonl"
        lines = log.read_bytes().splitlines(keepends=True)
        log.write_bytes(b"".join(lines[:-1]))  # someone with host access deletes the newest receipt
        print("deleted the newest local receipt (simulated tampering)")
        bad = dg("receipts", "verify", "--sink", sink, expect=1)
        check("sink is ahead" in (bad["error"] or ""), "truncation not caught")
        print("DEMO MARKER: sink-ok")

        admin.execute("DROP SCHEMA dg_demo CASCADE")
    print("\nDEMO OK")


def main() -> int:
    dsn = os.environ.get("DATAGRANT_DEMO_DSN")
    if not dsn:
        print(
            "set DATAGRANT_DEMO_DSN (or use `make demo`, which starts Postgres for you)",
            file=sys.stderr,
        )
        return 2
    work = Path(tempfile.mkdtemp(prefix="datagrant-demo-"))
    try:
        run(dsn, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)  # temp keys and receipts
        try:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP SCHEMA IF EXISTS dg_demo CASCADE"))
        except psycopg.Error:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
