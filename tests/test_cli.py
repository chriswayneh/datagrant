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
    assert main(["request", "--apply", "--dataset", "x"]) == EXIT_USAGE
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
    assert main(["sweep", "--apply"]) == EXIT_USAGE
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


@pytest.mark.parametrize(
    ("text", "dsn", "must_keep", "must_drop"),
    [
        # length 1: do not globally replace "x" (would turn "extra" into "e***tra")
        (
            "exception extra: postgresql://u:x@h/db failed",
            "postgresql://u:x@h/db",
            ("exception extra", "postgresql://u:***@h/db"),
            (":x@", "postgresql://u:x@h/db"),
        ),
        # length 2: "er" must not destroy "server error"
        (
            "server error: host=db password=er user=a",
            "host=db password=er user=a",
            ("server error", "password=***"),
            ("password=er",),
        ),
        # length 3: keep "abc" in diagnostics; still strip URI user:pass@
        (
            "role dg_abc cannot connect; postgresql://u:abc@h/db",
            "postgresql://u:abc@h/db",
            ("role dg_abc cannot connect", "postgresql://u:***@h/db"),
            (":abc@", "postgresql://u:abc@h/db"),
        ),
        # quoted conninfo, length 2
        (
            "bad conninfo password = 'pw' host=db",
            "host=db password=pw",
            ("password = ***",),
            ("password = 'pw'", "password='pw'"),
        ),
        # DSN-form patterns with no extracted dsn, short password
        (
            "postgresql://admin:pw@db/x failed",
            None,
            ("postgresql://admin:***@db/x",),
            (":pw@",),
        ),
        (
            "host=db password=ab user=admin failed",
            None,
            ("password=***",),
            ("password=ab",),
        ),
        # boundary 4: extracted password is replaced everywhere
        (
            "server said abcd is wrong",
            "host=db password=abcd",
            ("***",),
            ("abcd",),
        ),
        # longer than 4 (existing global-replace behavior)
        (
            "server said s3cr3tpw is wrong",
            "postgresql://u:s3cr3tpw@h/db",
            ("***",),
            ("s3cr3tpw", "s3cr3t"),
        ),
    ],
)
def test_redact_short_password_and_dsn_forms(
    text: str, dsn: str | None, must_keep: tuple[str, ...], must_drop: tuple[str, ...]
) -> None:
    out = redact(text, dsn)
    for needle in must_keep:
        assert needle in out, (needle, out)
    for needle in must_drop:
        assert needle not in out, (needle, out)


def test_connect_error_is_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    dsn = "postgresql://admin:hunter2zz@127.0.0.1:1/db?connect_timeout=1"
    assert main(["sweep", "--apply", "--dsn", dsn]) == EXIT_FAILED
    err = capsys.readouterr().err
    assert "cannot connect" in err and "hunter2zz" not in err


def test_connect_error_short_password_redacts_dsn_not_diagnostics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    dsn = "postgresql://admin:er@127.0.0.1:1/db?connect_timeout=1"
    assert main(["sweep", "--apply", "--dsn", dsn]) == EXIT_FAILED
    err = capsys.readouterr().err
    assert "cannot connect" in err
    assert "://admin:er@" not in err
    assert ":er@" not in err
    # length 2 must not mangle leftover diagnostic words such as "error"
    assert "errror" not in err and "s***v" not in err


def test_json_error_output() -> None:
    code, out = run(["--json", "receipts", "verify", "--pubkey", "zz"])
    assert code == EXIT_FAILED and "error" in json.loads(out[0])


def test_keys_init_export_and_verify_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    code, out = run(["keys", "init", "--apply", "--json"])
    pub = json.loads(out[0])["public_key"]
    assert code == EXIT_OK
    assert run(["keys", "init", "--apply"])[0] == EXIT_FAILED  # refuses overwrite
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


def test_verify_text_without_line_number(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    assert run(["keys", "init", "--apply"])[0] == EXIT_OK
    code, out = run(["receipts", "verify", "--receipt-log", str(tmp_path / "missing.jsonl")])
    assert code == EXIT_FAILED and out[0].startswith("FAILED: cannot read log")
    assert "None" not in out[0]
    code, out = run(["--json", "receipts", "verify", "--receipt-log", str(tmp_path / "m")])
    assert json.loads(out[0])["line"] is None
    log = tmp_path / "r.jsonl"
    log.write_bytes(b"")
    code, out = run(["receipts", "verify", "--receipt-log", str(log), "--expect-head", "1" * 64])
    assert code == EXIT_FAILED and out[0].startswith("FAILED: head hash differs")
    assert "None" not in out[0]


@pytest.mark.parametrize("apply", [True, False])
def test_keys_init_refuses_same_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apply: bool
) -> None:
    same = tmp_path / "k" / "one.key"
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(same))
    argv = ["keys", "init", "--signing-key", str(same)] + (["--apply"] if apply else [])
    assert run(argv)[0] == EXIT_USAGE
    assert not (tmp_path / "k").exists()  # nothing written
    from datagrant.keys import KeyFileError, init_keys

    with pytest.raises(KeyFileError, match="different files"):
        init_keys(hash_path=same, signing_path=same)
    assert not (tmp_path / "k").exists()


def _help(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    assert main([*argv, "--help"]) == EXIT_OK
    return " ".join(capsys.readouterr().out.split())


def test_key_help_mentions_dir_only_on_keys_init(capsys: pytest.CaptureFixture[str]) -> None:
    out = _help(["keys", "init"], capsys)
    assert "$DATAGRANT_SIGNING_KEY, then --dir, then ~/.config/datagrant" in out
    assert "$DATAGRANT_HASH_KEY, then --dir, then ~/.config/datagrant" in out
    for argv in (["request"], ["sweep"], ["revoke"], []):
        out = _help(argv, capsys)
        assert "--dir" not in out
        assert "then ~/.config/datagrant" in out


def test_preflight_help_says_dry_run(capsys: pytest.CaptureFixture[str]) -> None:
    out = _help([], capsys)
    assert "dry run; --apply creates state" in out
    assert "create state;" not in out


@pytest.mark.parametrize(
    ("argv", "secret"),
    [
        (["approve", "x", "--snowflake-dsn", "snowflake://admin:S3cretPw@acct/db"], "S3cretPw"),
        (["approve", "x", "--snowflake-dsn=snowflake://admin:S3cretPw@acct/db"], "S3cretPw"),
        (["keys", "init", "--dsn", "postgresql://u:PgPw1234@h/db"], "PgPw1234"),
        (["keys", "init", "--dsn=postgresql://u:PgPw1234@h/db"], "PgPw1234"),
        (["approve", "x", "--snowflake-dsn", "password=Pw9999"], "Pw9999"),
        (["approve", "x", "--snowflake-dsn=password=Pw9999"], "Pw9999"),
        (["keys", "init", "--dsn", "token=TOKVALUE123"], "TOKVALUE123"),
        (["keys", "init", "--dsn=token=TOKVALUE123"], "TOKVALUE123"),
        (["approve", "x", "--snowflake-dsn", "private_key=PKSECRET99"], "PKSECRET99"),
        (["keys", "init", "--dsn=private_key=PKSECRET99"], "PKSECRET99"),
    ],
)
def test_argparse_error_redacts_secret_flags(
    argv: list[str], secret: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == EXIT_USAGE
    err = capsys.readouterr().err
    assert secret not in err
    assert "<redacted>" in err


def test_argparse_error_redacts_env_dsns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://u:EnvPw9999@h/db")
    monkeypatch.setenv("DATAGRANT_SNOWFLAKE_DSN", "snowflake://admin:SfEnvPw88@acct/db")
    assert main(["keys", "init", "--bogus=postgresql://u:EnvPw9999@h/db"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "EnvPw9999" not in err
    assert main(["approve", "x", "--bogus=snowflake://admin:SfEnvPw88@acct/db"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "SfEnvPw88" not in err


def test_redact_does_not_mangle_oidc_token_flag() -> None:
    blob = "unrecognized arguments: --oidc-token=aaaaaaaa.bbbbbbbb.cccccccc"
    assert blob in redact(blob)
    assert "token=***" not in redact(blob)


def test_argparse_error_redacts_private_key_file_pwd_and_passcode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = [
        "approve",
        "x",
        "--snowflake-dsn",
        "account=a user=b private_key_file_pwd=KeyPw999 passcode=123456",
    ]
    assert main(argv) == EXIT_USAGE
    err = capsys.readouterr().err
    for secret in ("KeyPw999", "123456"):
        assert secret not in err


def test_argparse_error_redacts_env_and_flag_spaced_snowflake_dsn(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dsn = "account=a private_key_file_pwd=EnvPw777"
    monkeypatch.setenv("DATAGRANT_SNOWFLAKE_DSN", dsn)
    assert main(["approve", "x", "--snowflake-dsn", dsn]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "EnvPw777" not in err
    assert dsn not in err


def test_argparse_error_redacts_url_password_with_space(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["approve", "x", "--snowflake-dsn=snowflake://u:P@ss w0rd@acct"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "w0rd" not in err


def test_cli_redact_replaces_literal_dsn_before_regexes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsn = "account=a private_key_file_pwd=EnvPw777"
    monkeypatch.setenv("DATAGRANT_SNOWFLAKE_DSN", dsn)
    out = cli._cli_redact(f"fail --snowflake-dsn {dsn} trailing")
    assert "EnvPw777" not in out
    assert dsn not in out
    assert "trailing" in out
    assert "pass --dsn or set" in cli._cli_redact("no database: pass --dsn or set $DATAGRANT_DSN")


def test_sweep_missing_dsn_message_stays_verbatim(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv("DATAGRANT_SNOWFLAKE_DSN", raising=False)
    assert main(["sweep"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "pass --dsn or set $DATAGRANT_DSN" in err
    assert "pass --dsn <redacted>" not in err


def test_doctor_missing_dsn_message_stays_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    monkeypatch.delenv("DATAGRANT_SNOWFLAKE_DSN", raising=False)
    out: list[str] = []
    assert main(["doctor"], out.append) == EXIT_FAILED
    blob = "\n".join(out)
    assert "pass --dsn or set $DATAGRANT_DSN" in blob
    assert "pass --dsn <redacted>" not in blob


def test_redact_widens_secret_kv_keys() -> None:
    blob = "private_key_file_pwd=KeyPw999 passcode=123456 passphrase=Phs1 secret=Tok9"
    cleaned = redact(blob)
    for secret in ("KeyPw999", "123456", "Phs1", "Tok9"):
        assert secret not in cleaned


def test_err_and_warn_strip_snowflake_dsn_and_kv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import argparse

    monkeypatch.setenv("DATAGRANT_SNOWFLAKE_DSN", "snowflake://admin:S3cretPw@acct/db")
    args = argparse.Namespace(json=False, dsn=None, snowflake_dsn=None)
    ctx = cli.Ctx(args, lambda s: None)
    leak = (
        "fail snowflake://admin:S3cretPw@acct/db password=Pw9999 "
        "token=TOKVALUE123 private_key=PKSECRET99"
    )
    cli._err(ctx, leak, EXIT_USAGE)
    cli._warn(ctx, leak)
    err = capsys.readouterr().err
    for secret in ("S3cretPw", "Pw9999", "TOKVALUE123", "PKSECRET99"):
        assert secret not in err
