"""Snowflake --apply routing and grant engine: extra + DSN, mocked connector."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from datagrant import cli
from datagrant.cli import EXIT_FAILED, EXIT_OK, EXIT_USAGE
from datagrant.snowflake_support import (
    EXTRA_HINT,
    MAX_DSN_BYTES,
    SNOWFLAKE_DSN_ENV,
)

MIXED = """\
version: 1
approval: auto
max_duration: 8h
groups:
  ml: [alice]
datasets:
  - name: clinic
    database: clinicdb
    tables:
      - name: public.patients
        allowed_groups: [ml]
        columns: {id: passthrough, region: passthrough}
        row_filters: ["region = 'west'"]
        require_row_filter: true
  - name: snow_clinic
    engine: snowflake
    database: CLINIC_DB
    schema: PUBLIC
    tables:
      - name: PUBLIC.PATIENTS
        allowed_groups: [ml]
        columns: {PATIENT_ID: passthrough, SSN: hash}
"""

SF_REQ = [
    "request",
    "--dataset",
    "snow_clinic",
    "--table",
    "PUBLIC.PATIENTS",
    "--columns",
    "PATIENT_ID",
    "--duration",
    "1h",
    "--purpose",
    "eval",
    "--as-user",
    "alice",
]


def _policy(tmp_path: Path) -> Path:
    p = tmp_path / "mixed.yaml"
    p.write_text(MIXED)
    p.chmod(0o600)
    return p


def test_policy_check_mixed_file(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(["policy", "check", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["ok"] is True
    assert "clinic" in body["datasets"] and "snow_clinic" in body["datasets"]


def test_snowflake_dry_run_skips_postgres_dsn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main([*SF_REQ, "--policy", str(path), "--json"], out.append)
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["dry_run"] is True
    assert body["engine"] == "snowflake"
    assert "sql" in body
    assert any("CREATE USER" in s for s in body["sql"])
    assert all("BEGIN" not in s for s in body["sql"])
    text: list[str] = []
    assert cli.main([*SF_REQ, "--policy", str(path)], text.append) == EXIT_OK
    assert EXTRA_HINT in text[0]
    assert SNOWFLAKE_DSN_ENV in text[0]
    assert "not enabled yet" not in text[0]
    assert "BEGIN PRIVATE KEY" not in text[0]


def test_snowflake_apply_missing_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: False)
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB")
    path = _policy(tmp_path)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "datagrant[snowflake]" in err
    assert "snowflake://svc@xy12345" not in err


def test_snowflake_apply_missing_dsn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.delenv(SNOWFLAKE_DSN_ENV, raising=False)
    path = _policy(tmp_path)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "pass --snowflake-dsn or set $DATAGRANT_SNOWFLAKE_DSN" in err
    assert "pass --snowflake-dsn <redacted>" not in err
    assert "datagrant[snowflake]" not in err


class _FakeSf:
    def __init__(
        self,
        pending_row: tuple[Any, ...] | None = None,
        rowcount: int = 1,
        live_count: int = 0,
    ) -> None:
        self.queries: list[tuple[str, Any]] = []
        self.pending_row = pending_row
        self.rowcount = rowcount
        self.live_count = live_count
        self.fail_on: str | None = None
        self._one: tuple[Any, ...] | None = pending_row

    def cursor(self) -> _FakeSf:
        return self

    def execute(self, sql: str, params: Any = None) -> _FakeSf:
        self.queries.append((sql, params))
        if self.fail_on and self.fail_on.upper() in sql.upper():
            raise RuntimeError(f"stub:{self.fail_on}")
        su = sql.upper()
        if "COUNT(" in su and "GRANTS" in su:
            n = self.live_count
            if any(
                q[0].upper().startswith("INSERT") and "GRANTS" in q[0].upper()
                for q in self.queries[:-1]
            ):
                n += 1
            self._one = (n,)
        else:
            self._one = self.pending_row
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._one

    def fetchall(self) -> list[tuple[Any, ...]]:
        return []

    def close(self) -> None:
        return None


def _sf_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conn: _FakeSf) -> Path:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: conn)
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB")
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    return tmp_path / "r.jsonl"


def test_snowflake_apply_issues_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    conn = _FakeSf()
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _policy(tmp_path)
    dsn = "snowflake://svc@xy12345/CLINIC_DB?warehouse=WH"
    out: list[str] = []
    code = cli.main(
        [*SF_REQ, "--policy", str(path), "--apply", "--snowflake-dsn", dsn, "--json"],
        out.append,
    )
    err = capsys.readouterr().err
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["status"] == "granted"
    assert body["engine"] == "snowflake"
    assert "BEGIN PRIVATE KEY" in body["private_key"]
    sqls = [s for s, _p in conn.queries]
    assert any(s.startswith("CREATE USER") for s in sqls)
    assert any("DISABLED = FALSE" in s for s in sqls)
    assert any('GRANT USAGE ON WAREHOUSE "WH"' in s for s in sqls)
    assert all("BEGIN PRIVATE KEY" not in s for s in sqls)
    recs = [
        json.loads(line)["receipt"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert recs and recs[0]["event"] == "issued"
    assert "supersecret" not in err
    assert "supersecret" not in out[0]


def test_snowflake_dsn_too_long(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    path = _policy(tmp_path)
    huge = "s" * (MAX_DSN_BYTES + 1)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply", "--snowflake-dsn", huge])
    assert code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "too long" in err
    assert huge not in err


def test_whitespace_dsn_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "   ")
    path = _policy(tmp_path)
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply"])
    assert code == EXIT_USAGE
    assert SNOWFLAKE_DSN_ENV in capsys.readouterr().err


def test_denied_snowflake_request_does_not_need_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "datagrant.snowflake_support.driver_present",
        lambda: (_ for _ in ()).throw(AssertionError("driver probed on deny")),
    )
    path = _policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "request",
            "--dataset",
            "snow_clinic",
            "--table",
            "PUBLIC.PATIENTS",
            "--columns",
            "PATIENT_ID",
            "--duration",
            "1h",
            "--purpose",
            "eval",
            "--as-user",
            "eve",
            "--policy",
            str(path),
            "--json",
        ],
        out.append,
    )
    assert code == 1
    assert json.loads(out[0])["allowed"] is False


def test_dsn_kwargs_and_connect_never_need_network(monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant.snowflake_support import _dsn_kwargs, connect

    kw = _dsn_kwargs("snowflake://svc@xy12345/CLINIC_DB?warehouse=WH")
    assert kw["account"] == "xy12345"
    assert kw["user"] == "svc"
    assert kw["database"] == "CLINIC_DB"
    assert kw["warehouse"] == "WH"
    kv = _dsn_kwargs("account=xy user=svc warehouse=WH")
    assert kv["account"] == "xy" and kv["user"] == "svc"

    captured: dict[str, Any] = {}

    class _Mod:
        @staticmethod
        def connect(**kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return captured

    monkeypatch.setattr("datagrant.snowflake_support.load_connector", lambda: _Mod())
    monkeypatch.setattr("datagrant.snowflake_support._load_private_key", lambda p: b"DER")
    got = connect("snowflake://svc@xy12345/DB?private_key_file=/tmp/k.p8")
    assert got["account"] == "xy12345"
    assert got["user"] == "svc"
    assert got["paramstyle"] == "qmark"
    assert got["private_key"] == b"DER"
    assert "private_key_file" not in got
    assert got["paramstyle"] not in {"pyformat", "format"}
    with pytest.raises(Exception, match="password auth is not supported"):
        _dsn_kwargs("snowflake://svc:supersecret@xy12345/CLINIC_DB")
    with pytest.raises(Exception, match="password auth is not supported"):
        _dsn_kwargs("account=xy user=svc password=supersecret")
    with pytest.raises(Exception, match="private_key_file"):
        connect("snowflake://svc@xy12345/DB")
    with pytest.raises(Exception, match="must not set insecure_mode"):
        _dsn_kwargs("account=xy user=svc insecure_mode=true")
    with pytest.raises(Exception, match="must not set ocsp_fail_open"):
        _dsn_kwargs("account=xy user=svc ocsp_fail_open=false")
    with pytest.raises(Exception, match="protocol must be https"):
        _dsn_kwargs("account=xy user=svc protocol=http")
    with pytest.raises(Exception, match="protocol must be https"):
        _dsn_kwargs("http://svc@xy12345/CLINIC_DB")
    with pytest.raises(Exception, match="must be true or false"):
        _dsn_kwargs("account=xy user=svc insecure_mode=maybe")


def test_connect_refuses_pyformat_paramstyle(monkeypatch: pytest.MonkeyPatch) -> None:
    from datagrant.snowflake_support import SnowflakeSetupError, connect

    class _Frozen:
        @property
        def paramstyle(self) -> str:
            return "pyformat"

    class _Mod:
        paramstyle = "pyformat"

        @staticmethod
        def connect(**kwargs: Any) -> Any:
            return _Frozen()

    monkeypatch.setattr("datagrant.snowflake_support.load_connector", lambda: _Mod())
    monkeypatch.setattr("datagrant.snowflake_support._load_private_key", lambda p: b"DER")
    with pytest.raises(SnowflakeSetupError, match="qmark"):
        connect("account=xy user=svc private_key_file=/tmp/k.p8")


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_private_key_file_requires_0600(tmp_path: Path) -> None:
    from datagrant.snowflake_support import SnowflakeSetupError, _load_private_key

    key = tmp_path / "sf.p8"
    key.write_text("not-a-key")
    key.chmod(0o644)
    with pytest.raises(SnowflakeSetupError, match="chmod 600|group/other"):
        _load_private_key(str(key))
    key.chmod(0o600)
    with pytest.raises(SnowflakeSetupError, match="cannot load Snowflake private key"):
        _load_private_key(str(key))


def test_two_person_request_stores_public_key_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    conn = _FakeSf()
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _two_person_policy(tmp_path)
    out: list[str] = []
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    capsys.readouterr()
    assert code == EXIT_OK
    body = json.loads(out[0])
    assert body["status"] == "pending"
    assert body["engine"] == "snowflake"
    assert "BEGIN PRIVATE KEY" in body["private_key"]
    inserts = [
        (s, p) for s, p in conn.queries if s.startswith('INSERT INTO "DATAGRANT"."REQUESTS"')
    ]
    assert inserts
    _sql, params = inserts[0]
    blob = " ".join(str(x) for x in params)
    assert "BEGIN PRIVATE KEY" not in blob
    assert any("RSA_PUBLIC_KEY" in s or "PUBLIC_KEY" in str(p) for s, p in inserts)
    assert not any(s.startswith("CREATE USER") for s, _p in conn.queries)


def _sf_policy_with_filter(tmp_path: Path, *, two_person: bool = False) -> Path:
    text = MIXED
    if two_person:
        text = text.replace("approval: auto", "approval: two-person").replace(
            "groups:\n  ml: [alice]\n",
            "approvers: [sec]\ngroups:\n  ml: [alice]\n  sec: [carol]\n",
        )
    text = text.replace(
        "columns: {PATIENT_ID: passthrough, SSN: hash}",
        'columns: {PATIENT_ID: passthrough, SSN: hash}\n        row_filters: ["PATIENT_ID = 1"]',
    )
    path = tmp_path / ("two.yaml" if two_person else "sf.yaml")
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_snowflake_request_row_filter_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    path = _sf_policy_with_filter(tmp_path)
    argv = [*SF_REQ, "--row-filter", "PATIENT_ID = 1", "--policy", str(path), "--json"]
    out: list[str] = []
    assert cli.main(argv, out.append) == EXIT_FAILED
    body = json.loads(out[0])
    assert body["allowed"] is False
    assert any("row filters" in r for r in body["reasons"])
    out = []
    assert cli.main([*argv, "--apply"], out.append) == EXIT_FAILED
    applied = json.loads(out[0])
    assert applied["allowed"] is False
    recs = [
        json.loads(line)["receipt"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert recs and recs[0]["event"] == "denied"
    assert any("row filters" in r for r in recs[0]["details"]["reasons"])


def test_snowflake_approve_row_filter_not_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 11, 13, 3, 0, tzinfo=UTC)
    pending = (
        "aabbccddeeff",
        "alice",
        "snow_clinic",
        "PUBLIC.PATIENTS",
        '["PATIENT_ID"]',
        "PATIENT_ID = 1",
        3600,
        "eval",
        "a" * 64,
        "PUBKEY",
        "b" * 64,
        now.isoformat(),
        now.isoformat(),
        "pending",
        None,
    )
    conn = _FakeSf(pending_row=pending)
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: conn)
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB")
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    path = _sf_policy_with_filter(tmp_path, two_person=True)
    out: list[str] = []
    code = cli.main(
        [
            "approve",
            "aabbccddeeff",
            "--apply",
            "--policy",
            str(path),
            "--as-user",
            "carol",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_FAILED
    body = json.loads(out[0])
    assert body.get("approved") is False
    recs = [
        json.loads(line)["receipt"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert recs and recs[0]["event"] == "not_approved"
    assert any("row filters" in r for r in recs[0]["details"]["reasons"])


def _two_person_policy(tmp_path: Path) -> Path:
    pol = tmp_path / "two.yaml"
    pol.write_text(
        MIXED.replace("approval: auto", "approval: two-person").replace(
            "groups:\n  ml: [alice]\n",
            "approvers: [sec]\ngroups:\n  ml: [alice]\n  sec: [carol]\n",
        )
    )
    pol.chmod(0o600)
    return pol


def test_snowflake_approve_apply_issues_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple())
    code, body = _approve_apply(tmp_path, monkeypatch, conn)
    capsys.readouterr()
    assert code == EXIT_OK
    granted = json.loads(body)
    assert granted["status"] == "granted"
    assert granted["engine"] == "snowflake"
    sqls = [s for s, _p in conn.queries]
    claim = next(i for i, s in enumerate(sqls) if s.startswith('UPDATE "DATAGRANT"."REQUESTS"'))
    user = next(i for i, s in enumerate(sqls) if s.startswith("CREATE USER"))
    assert claim < user
    assert any("DISABLED = FALSE" in s for s in sqls)
    recs = [
        json.loads(line)["receipt"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert recs and recs[0]["event"] == "issued"


def test_snowflake_approve_identity_mode_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 11, 13, 3, 0, tzinfo=UTC)
    pending = (
        "aabbccddeeff",
        "alice",
        "snow_clinic",
        "PUBLIC.PATIENTS",
        '["PATIENT_ID"]',
        None,
        3600,
        "eval",
        "a" * 64,
        "PUBKEY",
        "b" * 64,
        now.isoformat(),
        now.isoformat(),
        "pending",
        json.dumps({"mode": "oidc"}),
    )
    conn = _FakeSf(pending_row=pending)
    monkeypatch.setattr("datagrant.snowflake_support.driver_present", lambda: True)
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: conn)
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB")
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    path = _two_person_policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "approve",
            "aabbccddeeff",
            "--apply",
            "--policy",
            str(path),
            "--as-user",
            "carol",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_FAILED
    body = json.loads(out[0])
    assert "identity mode" in body.get("error", "")
    recs = [
        json.loads(line)["receipt"]
        for line in (tmp_path / "r.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert recs and recs[0]["event"] == "not_approved"


def _pending_tuple(
    *,
    status: str = "pending",
    dataset: str = "snow_clinic",
    table: str = "PUBLIC.PATIENTS",
    columns: str = '["PATIENT_ID"]',
) -> tuple[Any, ...]:
    from datetime import UTC, datetime

    now = datetime(2026, 11, 13, 3, 0, tzinfo=UTC)
    return (
        "aabbccddeeff",
        "alice",
        dataset,
        table,
        columns,
        None,
        3600,
        "eval",
        "a" * 64,
        "PUBKEY",
        "b" * 64,
        now.isoformat(),
        now.isoformat(),
        status,
        None,
    )


def _approve_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conn: _FakeSf,
    *,
    policy: Path | None = None,
    as_user: str = "carol",
) -> tuple[int, str]:
    _sf_keys(tmp_path, monkeypatch, conn)
    path = policy or _two_person_policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "approve",
            "aabbccddeeff",
            "--apply",
            "--policy",
            str(path),
            "--as-user",
            as_user,
            "--json",
        ],
        out.append,
    )
    return code, out[0] if out else ""


def test_snowflake_approve_double_claim_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple(), rowcount=0)
    code, body = _approve_apply(tmp_path, monkeypatch, conn)
    assert code == EXIT_FAILED
    assert "not pending or expired" in body
    assert not any("CREATE USER" in s for s, _p in conn.queries)
    claim = next(s for s, _p in conn.queries if s.startswith('UPDATE "DATAGRANT"."REQUESTS"'))
    assert "EXPIRES_AT > CURRENT_TIMESTAMP()" in claim
    assert "?" in claim


def test_snowflake_approve_expired_pending_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple(), rowcount=0)
    code, body = _approve_apply(tmp_path, monkeypatch, conn)
    assert code == EXIT_FAILED
    assert "not pending or expired" in body
    assert not any(p == ("failed", "aabbccddeeff") for _s, p in conn.queries)


def test_snowflake_approve_apply_failure_marks_request_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple(), rowcount=1)
    conn.fail_on = "CREATE USER"
    code, _body = _approve_apply(tmp_path, monkeypatch, conn)
    assert code == EXIT_FAILED
    assert any(p == ("failed", "aabbccddeeff") for _s, p in conn.queries)


def _receipt_events(tmp_path: Path) -> list[dict[str, Any]]:
    log = tmp_path / "r.jsonl"
    if not log.exists():
        return []
    return [json.loads(line)["receipt"] for line in log.read_text().splitlines() if line.strip()]


SNOW_LAB = """\
  - name: snow_lab
    engine: snowflake
    database: LAB_DB
    schema: PUBLIC
    tables:
      - name: PUBLIC.SAMPLES
        allowed_groups: [ml]
        columns: {SAMPLE_ID: passthrough}
"""

SF_REQ_LAB = [
    "request",
    "--dataset",
    "snow_lab",
    "--table",
    "PUBLIC.SAMPLES",
    "--columns",
    "SAMPLE_ID",
    "--duration",
    "1h",
    "--purpose",
    "eval",
    "--as-user",
    "alice",
]


def _policy_text(
    *, two_person: bool = False, top: str = "", table_extra: str = "", extra_dataset: str = ""
) -> str:
    text = MIXED
    if two_person:
        text = text.replace("approval: auto", "approval: two-person").replace(
            "groups:\n  ml: [alice]\n",
            "approvers: [sec]\ngroups:\n  ml: [alice]\n  sec: [carol]\n",
        )
    if top:
        text = text.replace("version: 1\n", f"version: 1\n{top}\n")
    if table_extra:
        text = text.replace(
            "columns: {PATIENT_ID: passthrough, SSN: hash}",
            "columns: {PATIENT_ID: passthrough, SSN: hash}\n" + table_extra,
        )
    if extra_dataset:
        text = text.rstrip() + "\n" + extra_dataset
    return text


def _write_policy(tmp_path: Path, text: str, name: str = "p.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_snowflake_apply_over_concurrent_cap_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(live_count=1)
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _write_policy(tmp_path, _policy_text(top="max_concurrent_grants: 1"))
    out: list[str] = []
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_FAILED
    body = json.loads(out[0])
    assert body["allowed"] is False
    assert any("max_concurrent_grants" in r for r in body["reasons"])
    assert not any(s.startswith("CREATE USER") for s, _p in conn.queries)
    recs = _receipt_events(tmp_path)
    assert recs and recs[0]["event"] == "denied"
    count = next(s for s, _p in conn.queries if "COUNT(" in s)
    assert "REQUESTER = ?" in count
    assert "DATASET" not in count
    assert "STATUS IN (?, ?, ?)" in count


def test_snowflake_approve_over_concurrent_cap_not_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple(), live_count=1)
    path = _write_policy(
        tmp_path, _policy_text(two_person=True, top="max_concurrent_grants: 1"), "two.yaml"
    )
    code, body = _approve_apply(tmp_path, monkeypatch, conn, policy=path)
    assert code == EXIT_FAILED
    denied = json.loads(body)
    assert denied.get("approved") is False
    assert any("max_concurrent_grants" in r for r in denied["reasons"])
    assert not any(s.startswith("CREATE USER") for s, _p in conn.queries)
    recs = _receipt_events(tmp_path)
    assert recs and recs[0]["event"] == "not_approved"


def test_snowflake_policy_wide_cap_spans_datasets_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(live_count=1)
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _write_policy(
        tmp_path,
        _policy_text(top="max_concurrent_grants: 1", extra_dataset=SNOW_LAB),
        "span.yaml",
    )
    out: list[str] = []
    code = cli.main([*SF_REQ_LAB, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_FAILED
    body = json.loads(out[0])
    assert body["allowed"] is False
    assert any("max_concurrent_grants" in r for r in body["reasons"])
    assert not any(s.startswith("CREATE USER") for s, _p in conn.queries)
    count_sql, count_params = next(q for q in conn.queries if "COUNT(" in q[0])
    assert "DATASET" not in count_sql
    assert count_params[0] == "alice"
    recs = _receipt_events(tmp_path)
    assert recs and recs[0]["event"] == "denied"


def test_snowflake_policy_wide_cap_spans_datasets_on_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pending = _pending_tuple(dataset="snow_lab", table="PUBLIC.SAMPLES", columns='["SAMPLE_ID"]')
    conn = _FakeSf(pending_row=pending, live_count=1)
    path = _write_policy(
        tmp_path,
        _policy_text(two_person=True, top="max_concurrent_grants: 1", extra_dataset=SNOW_LAB),
        "span-two.yaml",
    )
    code, body = _approve_apply(tmp_path, monkeypatch, conn, policy=path)
    assert code == EXIT_FAILED
    denied = json.loads(body)
    assert denied.get("approved") is False
    assert any("max_concurrent_grants" in r for r in denied["reasons"])
    assert not any(s.startswith("CREATE USER") for s, _p in conn.queries)
    count_sql, count_params = next(q for q in conn.queries if "COUNT(" in q[0])
    assert "DATASET" not in count_sql
    assert count_params[0] == "alice"
    recs = _receipt_events(tmp_path)
    assert recs and recs[0]["event"] == "not_approved"


def test_snowflake_approve_passes_dsn_warehouse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple())
    _sf_keys(tmp_path, monkeypatch, conn)
    monkeypatch.setenv(SNOWFLAKE_DSN_ENV, "snowflake://svc@xy12345/CLINIC_DB?warehouse=WH")
    path = _two_person_policy(tmp_path)
    out: list[str] = []
    code = cli.main(
        [
            "approve",
            "aabbccddeeff",
            "--apply",
            "--policy",
            str(path),
            "--as-user",
            "carol",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_OK
    assert any('GRANT USAGE ON WAREHOUSE "WH"' in s for s, _p in conn.queries)


def test_snowflake_request_duration_and_max_columns_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf()
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _write_policy(
        tmp_path,
        _policy_text(table_extra="        max_columns: 1"),
    )
    out: list[str] = []
    long_req = [
        *SF_REQ[: SF_REQ.index("--duration") + 1],
        "24h",
        *SF_REQ[SF_REQ.index("--duration") + 2 :],
        "--policy",
        str(path),
        "--apply",
        "--json",
    ]
    assert cli.main(long_req, out.append) == EXIT_FAILED
    body = json.loads(out[0])
    assert body["allowed"] is False
    assert any("exceeds max" in r for r in body["reasons"])
    out = []
    wide = [
        *SF_REQ[: SF_REQ.index("--columns") + 1],
        "PATIENT_ID,SSN",
        *SF_REQ[SF_REQ.index("--columns") + 2 :],
        "--policy",
        str(path),
        "--apply",
        "--json",
    ]
    assert cli.main(wide, out.append) == EXIT_FAILED
    wide_body = json.loads(out[0])
    assert any("max_columns" in r for r in wide_body["reasons"])
    recs = _receipt_events(tmp_path)
    assert recs and recs[0]["event"] == "denied"


def test_snowflake_approve_self_and_distinct_groups_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf(pending_row=_pending_tuple())
    code, body = _approve_apply(tmp_path, monkeypatch, conn, as_user="alice")
    assert code == EXIT_FAILED
    denied = json.loads(body)
    assert denied.get("approved") is False
    assert any("different person" in r for r in denied["reasons"])
    sod = _policy_text(two_person=True, top="separation_of_duties: distinct-groups")
    sod = sod.replace("ml: [alice]", "ml: [alice, carol]")
    conn2 = _FakeSf(pending_row=_pending_tuple())
    monkeypatch.setattr("datagrant.snowflake_support.connect", lambda dsn: conn2)
    path = _write_policy(tmp_path, sod, "sod.yaml")
    out: list[str] = []
    code = cli.main(
        [
            "approve",
            "aabbccddeeff",
            "--apply",
            "--policy",
            str(path),
            "--as-user",
            "carol",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_FAILED
    sod_body = json.loads(out[0])
    assert any("distinct-groups" in r for r in sod_body["reasons"])
    recs = _receipt_events(tmp_path)
    assert recs and recs[-1]["event"] == "not_approved"


def test_snowflake_quorum_not_implemented(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeSf(pending_row=_pending_tuple())
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _write_policy(
        tmp_path,
        _policy_text(two_person=True, top="approvals_required: 2"),
        "q.yaml",
    )
    out: list[str] = []
    code = cli.main([*SF_REQ, "--policy", str(path), "--apply", "--json"], out.append)
    assert code == EXIT_USAGE
    assert "approvals_required > 1" in out[0]
    assert not any(s.startswith('INSERT INTO "DATAGRANT"."REQUESTS"') for s, _p in conn.queries)
    out = []
    code = cli.main(
        [
            "approve",
            "aabbccddeeff",
            "--apply",
            "--policy",
            str(path),
            "--as-user",
            "carol",
            "--json",
        ],
        out.append,
    )
    assert code == EXIT_USAGE
    assert "approvals_required > 1" in out[0]
    assert not any(s.startswith("CREATE USER") for s, _p in conn.queries)


def test_snowflake_pending_ttl_over_cap_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _FakeSf()
    _sf_keys(tmp_path, monkeypatch, conn)
    path = _write_policy(tmp_path, _policy_text(two_person=True, top="pending_ttl: 1h"), "ttl.yaml")
    out: list[str] = []
    code = cli.main(
        [*SF_REQ, "--policy", str(path), "--pending-ttl", "2h", "--apply", "--json"],
        out.append,
    )
    assert code == EXIT_USAGE
    assert "pending_ttl" in out[0]
    assert conn.queries == []
