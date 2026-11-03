from __future__ import annotations

import json
from pathlib import Path

import pytest

from datagrant import __version__, cli
from datagrant.cli import EXIT_FAILED, EXIT_OK, EXIT_USAGE, main, redact

EXAMPLE = Path(__file__).parent.parent / "examples" / "policy.yaml"


def run(argv: list[str]) -> tuple[int, list[str]]:
    out: list[str] = []
    return main(argv, out.append), out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"datagrant {__version__}"


def test_usage_errors_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == EXIT_USAGE
    assert main(["request", "--dataset", "x"]) == EXIT_USAGE
    assert main(["bogus"]) == EXIT_USAGE
    assert main(["--help"]) == EXIT_OK


def test_policy_check_ok_and_bad(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(["policy", "check", str(EXAMPLE), "--json"])
    assert code == EXIT_OK and json.loads(out[0])["ok"] is True
    bad = tmp_path / "p.yaml"
    bad.write_text("version: 2\n")
    assert main(["policy", "check", str(bad)]) == EXIT_FAILED
    assert "datagrant: error:" in capsys.readouterr().err


def test_missing_dsn_and_policy_are_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv("DATAGRANT_POLICY", raising=False)
    assert main(["sweep"]) == EXIT_USAGE
    base = [
        "request",
        "--dataset",
        "clinic",
        "--table",
        "public.patients",
        "--columns",
        "zip",
        "--duration",
        "1h",
        "--purpose",
        "x",
    ]
    assert main(base) == EXIT_USAGE  # no policy
    assert (
        main(
            [
                *base,
                "--policy",
                str(EXAMPLE),
                "--as-user",
                "alice",
                "--row-filter",
                "region = 'west'",
            ]
        )
        == EXIT_USAGE
    )  # no DSN


def test_denied_request_exit_1_without_db() -> None:
    code, out = run(
        [
            "request",
            "--policy",
            str(EXAMPLE),
            "--as-user",
            "mallory",
            "--json",
            "--dataset",
            "clinic",
            "--table",
            "public.patients",
            "--columns",
            "zip",
            "--duration",
            "1h",
            "--purpose",
            "x",
            "--dsn",
            "postgresql://x",
        ]
    )
    data = json.loads(out[0])
    assert code == EXIT_FAILED and data["allowed"] is False and data["requester"] == "mallory"


@pytest.mark.parametrize(
    ("text", "dsn"),
    [
        ("connection to postgresql://admin:s3cr3tpw@db/x failed", None),
        ("bad conninfo host=db password=s3cr3tpw user=a", None),
        ("bad conninfo password = 's3cr3t pw' x", None),
        ("server said s3cr3tpw is wrong", "host=db password=s3cr3tpw"),
        ("server said s3cr3tpw is wrong", "postgresql://u:s3cr3tpw@h/db"),
    ],
)
def test_redact(text: str, dsn: str | None) -> None:
    out = redact(text, dsn)
    assert "s3cr3t" not in out and "***" in out


def test_connect_error_is_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    dsn = "postgresql://admin:hunter2zz@127.0.0.1:1/db?connect_timeout=1"
    assert main(["sweep", "--dsn", dsn]) == EXIT_FAILED
    err = capsys.readouterr().err
    assert "cannot connect" in err and "hunter2zz" not in err


def test_json_error_output() -> None:
    code, out = run(["--json", "receipts", "verify", "--pubkey", "zz"])
    assert code == EXIT_FAILED and "error" in json.loads(out[0])


def test_keys_init_export_and_verify_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    code, out = run(["keys", "init", "--json"])
    pub = json.loads(out[0])["public_key"]
    assert code == EXIT_OK
    assert run(["keys", "init"])[0] == EXIT_FAILED  # refuses overwrite
    code, out = run(["keys", "export-pubkey"])
    assert code == EXIT_OK and out == [pub]
    log = tmp_path / "r.jsonl"
    log.write_bytes(b"")
    code, out = run(["receipts", "verify", "--receipt-log", str(log), "--pubkey", pub])
    assert code == EXIT_OK and out[0].startswith("OK: 0 receipt(s)")
    log.write_bytes(b"junk\n")
    code, out = run(["receipts", "verify", "--receipt-log", str(log)])
    assert code == EXIT_FAILED and "FAILED at line 1" in out[0]


def test_exit_for_mapping() -> None:
    from datagrant.pg.revoke import RevokeResult

    ok = RevokeResult("a", "revoked")
    assert cli._exit_for([ok], None) == EXIT_OK
    assert cli._exit_for([RevokeResult("a", "failed")], None) == cli.EXIT_REVOKE_FAILED
    assert (
        cli._exit_for([RevokeResult("a", "revoked", receipt_error="x")], None) == cli.EXIT_RECEIPT
    )
    assert cli._exit_for([ok], "no key") == cli.EXIT_RECEIPT
    assert cli._exit_for([], "no key") == EXIT_OK
    assert (
        len(
            {cli.EXIT_OK, cli.EXIT_FAILED, cli.EXIT_USAGE, cli.EXIT_RECEIPT, cli.EXIT_REVOKE_FAILED}
        )
        == 5
    )


def test_identity_default_is_os_user(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    monkeypatch.setattr(cli.getpass, "getuser", lambda: "osuser")
    assert cli._identity(argparse.Namespace(as_user=None)) == ("osuser", "os")
    assert cli._identity(argparse.Namespace(as_user="bob")) == ("bob", "flag")
