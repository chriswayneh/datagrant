#!/usr/bin/env python3
"""Snowflake dry-run demo. No DSN, no --apply, no credentials.

Prints the SQL datagrant would emit for a fictional CLINIC_DB.PATIENTS
grant: TYPE=SERVICE user, secure view FROM ... AS "SRC", redacted RSA
public key. Run via `python3 scripts/demo_snowflake.py` or
`./scripts/record-gifs.sh`.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from datagrant import __version__
from datagrant.cli import main as cli

POLICY = """\
# fictional names only; no real account, warehouse, or key
version: 1
approval: auto
max_duration: 8h
groups:
  ml-team: [alice]
datasets:
  - name: snow_clinic
    engine: snowflake
    database: CLINIC_DB
    schema: PUBLIC
    tables:
      - name: PUBLIC.PATIENTS
        allowed_groups: [ml-team]
        max_duration: 4h
        columns:
          PATIENT_ID: passthrough
          SSN: hash
          FULL_NAME: redact
          BIRTH_DATE: "null"
        filter_columns: [REGION]
        row_filters:
          - "REGION = 'west'"
          - "BIRTH_DATE IS NULL"
"""


def dg(argv: list[str]) -> str:
    out: list[str] = []
    code = cli(argv, out.append)
    text = "\n".join(out)
    if code != 0:
        raise SystemExit(f"DEMO FAILED: {' '.join(argv)} exit {code}\n{text}")
    return text


def shown(argv: list[str], work: Path) -> str:
    return " ".join(argv).replace(str(work), "<tmp>")


def run(work: Path) -> None:
    os.environ.update(
        {
            "DATAGRANT_SIGNING_KEY": str(work / "signing.key"),
            "DATAGRANT_HASH_KEY": str(work / "hash.key"),
            "DATAGRANT_RECEIPT_LOG": str(work / "receipts.jsonl"),
        }
    )
    os.environ.pop("DATAGRANT_DSN", None)
    os.environ.pop("DATAGRANT_SNOWFLAKE_DSN", None)

    print("# datagrant snowflake demo, v0.6.0 (dry-run SQL only, no account)")
    print("$ datagrant --version")
    print(f"datagrant {__version__}")

    policy = work / "policy.yaml"
    policy.write_text(POLICY)
    policy.chmod(0o600)

    print("\n=== DEMO STEP 1: keys and policy check")
    print("$ datagrant keys init --apply")
    print(dg(["keys", "init", "--apply"]))
    cmd = ["policy", "check", str(policy)]
    print(f"$ datagrant {shown(cmd, work)}")
    print(dg(cmd))

    print("=== DEMO STEP 2: request dry-run (hash, redact, null, REGION filter)")
    req = [
        "request",
        "--policy",
        str(policy),
        "--as-user",
        "alice",
        "--dataset",
        "snow_clinic",
        "--table",
        "PUBLIC.PATIENTS",
        "--columns",
        "PATIENT_ID,SSN,FULL_NAME,BIRTH_DATE",
        "--row-filter",
        "REGION = 'west'",
        "--duration",
        "2h",
        "--purpose",
        "eval",
    ]
    print(f"$ datagrant {shown(req, work)}")
    text = dg(req)
    print(text)
    if "CREATE SECURE VIEW" not in text or 'AS "SRC"' not in text:
        raise SystemExit("DEMO FAILED: missing secure view / SRC alias")
    if "BEGIN PRIVATE KEY" in text or "RSA_PUBLIC_KEY = '<redacted>'" not in text:
        raise SystemExit("DEMO FAILED: key material leaked or not redacted")
    if "snowflake://" in text or "private_key_file" in text:
        raise SystemExit("DEMO FAILED: DSN leaked into dry-run output")
    print("DEMO MARKER: snowflake-view-ok")

    print("\n=== DEMO STEP 3: IS NULL filter on a null-masked column uses SRC.BIRTH_DATE")
    req_null = [
        "request",
        "--policy",
        str(policy),
        "--as-user",
        "alice",
        "--dataset",
        "snow_clinic",
        "--table",
        "PUBLIC.PATIENTS",
        "--columns",
        "PATIENT_ID,BIRTH_DATE",
        "--row-filter",
        "BIRTH_DATE IS NULL",
        "--duration",
        "2h",
        "--purpose",
        "eval",
    ]
    print(f"$ datagrant {shown(req_null, work)}")
    text = dg(req_null)
    print(text)
    if '"SRC"."BIRTH_DATE" IS NULL' not in text:
        raise SystemExit("DEMO FAILED: IS NULL filter was not SRC-qualified")
    print("DEMO MARKER: snowflake-null-filter-ok")
    print("\nDEMO OK")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="datagrant-sf-demo-"))
    try:
        run(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
