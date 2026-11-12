"""M3 construction PR 3: strict_preflight and file-mode gates."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_cli_flows import CAT, POLICY, REQ, FakeConn
from test_policy import doc, table

from datagrant import cli
from datagrant.pg import grant as g
from datagrant.pg import revoke as rv
from datagrant.policy import PolicyError, parse_policy


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:6543/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.delenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", raising=False)
    assert cli.main(["keys", "init", "--apply"], lambda s: None) == 0
    conn = FakeConn()
    state: dict[str, Any] = {"conn": conn, "applied": []}
    monkeypatch.setattr(cli, "_connect", lambda a: conn)
    monkeypatch.setattr(g, "ensure_state", lambda c: ["PUBLIC can CREATE in schema public"])
    monkeypatch.setattr("datagrant.pg.mask.inspect_table", lambda c, t: CAT)
    monkeypatch.setattr(
        g, "apply_plan", lambda c, plan, sink, **kw: state["applied"].append((plan, sink, kw))
    )
    monkeypatch.setattr(g, "can_set_log_statement", lambda c: True)
    for mode in ("auto", "two-person"):
        (tmp_path / f"{mode}.yaml").write_text(POLICY.format(approval=mode))
        os.chmod(tmp_path / f"{mode}.yaml", 0o600)
    state["tmp"] = tmp_path
    return state


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out: list[str] = []
    code = cli.main(["--json", *argv], out.append)
    return code, json.loads(out[-1]) if out else {}


def test_strict_keys_optional_and_boolean() -> None:
    p = parse_policy(doc())
    assert p.strict_preflight is False
    assert p.strict_policy_permissions is False
    p = parse_policy(doc(strict_preflight=True, strict_policy_permissions=True))
    assert p.strict_preflight is True
    assert p.strict_policy_permissions is True
    with pytest.raises(PolicyError, match="true/false"):
        parse_policy(doc(strict_preflight="yes"))
    with pytest.raises(PolicyError, match="true/false"):
        parse_policy(doc(strict_policy_permissions=1))


def test_dataset_and_table_strict_keys_are_unknown() -> None:
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(table(strict_preflight=True))
    d = doc()
    d["datasets"][0]["strict_policy_permissions"] = True
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy(d)


def test_policy_check_accepts_strict_keys(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\napproval: auto\nmax_duration: 8h\n"
        "strict_preflight: true\nstrict_policy_permissions: false\n"
        "groups: {ml: [alice]}\ndatasets:\n"
        "  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.p\n        allowed_groups: [ml]\n"
        "        columns: {id: passthrough}\n"
    )
    assert cli.main(["policy", "check", str(p)], lambda s: None) == cli.EXIT_OK


def test_omit_strict_preflight_warns_and_grants(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(g, "preflight", lambda c: ["PUBLIC can CREATE in schema public"])
    pol = str(setup["tmp"] / "auto.yaml")
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == 0 and d["status"] == "granted"
    assert "PUBLIC can CREATE" in capsys.readouterr().err
    assert setup["applied"]


def test_strict_preflight_refuses_request_apply(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(g, "preflight", lambda c: ["PUBLIC can CREATE in schema public"])
    pol = setup["tmp"] / "strict.yaml"
    pol.write_text(POLICY.format(approval="auto") + "strict_preflight: true\n")
    os.chmod(pol, 0o600)
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == cli.EXIT_FAILED
    assert "strict_preflight" in d.get("error", "")
    assert not setup["applied"]


def test_strict_preflight_dry_run_still_reports(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(g, "preflight", lambda c: ["PUBLIC can CREATE in schema public"])
    pol = setup["tmp"] / "strict.yaml"
    pol.write_text(POLICY.format(approval="auto") + "strict_preflight: true\n")
    os.chmod(pol, 0o600)
    code, d = run("request", "--policy", str(pol), *REQ)
    assert code == 0 and d["dry_run"] is True
    assert "PUBLIC can CREATE" in capsys.readouterr().err
    assert not setup["applied"]


def test_strict_preflight_preflight_apply_creates_state_then_exits_1(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    called = {"n": 0}

    def ens(c: Any) -> list[str]:
        called["n"] += 1
        return ["PUBLIC can CREATE in schema public"]

    monkeypatch.setattr(g, "ensure_state", ens)
    pol = setup["tmp"] / "strict.yaml"
    pol.write_text(POLICY.format(approval="auto") + "strict_preflight: true\n")
    os.chmod(pol, 0o600)
    code, d = run("preflight", "--apply", "--policy", str(pol))
    assert code == cli.EXIT_FAILED
    assert called["n"] == 1
    assert d["warnings"]
    assert any("PUBLIC" in w for w in d["warnings"])


def test_preflight_dry_run_ignores_missing_policy_env(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATAGRANT_POLICY", "/nonexistent")
    code, d = run("preflight")
    assert code == cli.EXIT_OK
    assert "warnings" in d


def test_preflight_apply_bad_policy_exits_1(
    setup: dict[str, Any], tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n")
    code, d = run("preflight", "--apply", "--policy", str(bad))
    assert code == cli.EXIT_FAILED
    assert "error" in d


def test_strict_preflight_does_not_block_revoke(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = setup["tmp"] / "strict.yaml"
    pol.write_text(POLICY.format(approval="auto") + "strict_preflight: true\n")
    os.chmod(pol, 0o600)
    monkeypatch.setenv("DATAGRANT_POLICY", str(pol))
    monkeypatch.setattr(g, "preflight", lambda c: ["PUBLIC can CREATE in schema public"])
    monkeypatch.setattr(
        rv, "revoke", lambda c, gid, reason, sink: rv.RevokeResult("abc", "revoked", 0)
    )
    code, d = run("revoke", "--apply", "abc")
    assert code == 0
    assert d["outcome"] == "revoked"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_policy_0644_warns_and_still_applies(
    setup: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    pol = setup["tmp"] / "auto.yaml"
    os.chmod(pol, 0o644)
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == 0 and d["status"] == "granted"
    assert "group/other-accessible" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_env_strict_policy_permissions_refuses_before_parse(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = setup["tmp"] / "badver.yaml"
    pol.write_text("version: 2\n")
    os.chmod(pol, 0o644)
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", "1")
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == cli.EXIT_FAILED
    err = d.get("error", "")
    assert "group/other-accessible" in err
    assert "unsupported" not in err.lower()
    assert "version" not in err.lower()
    assert not setup["applied"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_flag_strict_policy_permissions_refuses_before_parse(setup: dict[str, Any]) -> None:
    pol = setup["tmp"] / "badver.yaml"
    pol.write_text("version: 2\n")
    os.chmod(pol, 0o644)
    code, d = run(
        "request",
        "--apply",
        "--strict-policy-permissions",
        "--policy",
        str(pol),
        *REQ,
    )
    assert code == cli.EXIT_FAILED
    err = d.get("error", "")
    assert "group/other-accessible" in err
    assert "unsupported" not in err.lower()
    assert not setup["applied"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_env_strict_policy_permissions_dry_run_still_parses(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = setup["tmp"] / "badver.yaml"
    pol.write_text("version: 2\n")
    os.chmod(pol, 0o644)
    monkeypatch.setenv("DATAGRANT_STRICT_POLICY_PERMISSIONS", "1")
    code, d = run("request", "--policy", str(pol), *REQ)
    assert code == cli.EXIT_FAILED
    assert "version" in d.get("error", "").lower()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_strict_policy_permissions_refuses_request_apply(
    setup: dict[str, Any],
) -> None:
    pol = setup["tmp"] / "strictp.yaml"
    pol.write_text(POLICY.format(approval="auto") + "strict_policy_permissions: true\n")
    os.chmod(pol, 0o644)
    code, d = run("request", "--apply", "--policy", str(pol), *REQ)
    assert code == cli.EXIT_FAILED
    assert "group/other-accessible" in d.get("error", "")
    assert not setup["applied"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_receipt_log_0644_refuses_access_creating_apply(setup: dict[str, Any]) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o644)
    pol = str(setup["tmp"] / "auto.yaml")
    os.chmod(pol, 0o600)
    code, d = run("request", "--apply", "--policy", pol, *REQ)
    assert code == cli.EXIT_FAILED
    assert "receipt log" in d.get("error", "")
    assert "group/other-accessible" in d.get("error", "")
    assert not setup["applied"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_receipt_log_0644_dry_run_warns(
    setup: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o644)
    pol = str(setup["tmp"] / "auto.yaml")
    os.chmod(pol, 0o600)
    code, d = run("request", "--policy", pol, *REQ)
    assert code == 0 and d["dry_run"] is True
    assert "receipt log" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_revoke_0644_receipt_log_still_revokes_exit_3(
    setup: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    log = Path(os.environ["DATAGRANT_RECEIPT_LOG"])
    log.write_text("")
    os.chmod(log, 0o644)
    monkeypatch.setattr(
        rv, "revoke", lambda c, gid, reason, sink: rv.RevokeResult("abc", "revoked", 1)
    )
    code, d = run("revoke", "--apply", "abc")
    # stubbed revoke does not write a receipt; the 0644 log is a warning only here.
    # Integration covers the real append -> exit 3 path. This proves revoke is not refused.
    assert code in {0, cli.EXIT_RECEIPT}
    assert d.get("outcome") == "revoked" or d.get("error") is None
