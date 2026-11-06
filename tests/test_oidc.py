from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from datagrant import oidc
from datagrant.cli import EXIT_OK, main
from datagrant.oidc import (
    INSECURE_LOCALHOST_ENV,
    IdentityConfig,
    IdentityError,
    read_token_file,
    redact_token,
    token_sha256,
    verify_oidc_token,
)
from datagrant.policy import PolicyError, Request, evaluate, parse_policy

NOW = 1_800_000_000.0
INSECURE_ENV = {INSECURE_LOCALHOST_ENV: "1"}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64u(n: int, length: int | None = None) -> str:
    size = length if length is not None else max(1, (n.bit_length() + 7) // 8)
    return _b64u(n.to_bytes(size, "big"))


class KeySet:
    """In-memory test IdP keys for RS256, ES256 and EdDSA."""

    def __init__(self) -> None:
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_priv = ec.generate_private_key(ec.SECP256R1())
        self.ed_priv = ed25519.Ed25519PrivateKey.generate()

    def jwks(self) -> list[dict[str, Any]]:
        rn = self.rsa_priv.public_key().public_numbers()
        en = self.ec_priv.public_key().public_numbers()
        ed_raw = self.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return [
            {
                "kty": "RSA",
                "kid": "rsa-1",
                "use": "sig",
                "alg": "RS256",
                "n": _int_b64u(rn.n),
                "e": _int_b64u(rn.e),
            },
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "ec-1",
                "use": "sig",
                "alg": "ES256",
                "x": _int_b64u(en.x, 32),
                "y": _int_b64u(en.y, 32),
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "ed-1",
                "use": "sig",
                "alg": "EdDSA",
                "x": _b64u(ed_raw),
            },
            {"kty": "RSA", "kid": "enc-ignored", "use": "enc", "n": "AQAB", "e": "AQAB"},
        ]

    def sign(
        self,
        claims: Mapping[str, Any],
        *,
        alg: str = "EdDSA",
        kid: str | None = None,
        extra_header: Mapping[str, Any] | None = None,
    ) -> str:
        default_kids = {"RS256": "rsa-1", "ES256": "ec-1", "EdDSA": "ed-1"}
        hdr: dict[str, Any] = {"typ": "JWT", "alg": alg, "kid": kid or default_kids.get(alg, "k")}
        if extra_header:
            hdr.update(extra_header)
        h_b64 = _b64u(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
        p_b64 = _b64u(json.dumps(dict(claims), separators=(",", ":")).encode("utf-8"))
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        if alg == "RS256":
            sig = self.rsa_priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256":
            der = self.ec_priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            r, s = utils.decode_dss_signature(der)
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        elif alg == "EdDSA":
            sig = self.ed_priv.sign(signing_input)
        elif alg == "none":
            return f"{h_b64}.{p_b64}."
        else:
            raise ValueError(alg)
        return f"{h_b64}.{p_b64}.{_b64u(sig)}"


@pytest.fixture(scope="module")
def keys() -> KeySet:
    return KeySet()


class IdpState:
    def __init__(self, keys: KeySet) -> None:
        self.issuer = ""
        self.jwks_keys = keys.jwks()
        self.disc_issuer_override: str | None = None
        self.redirect_to: str | None = None
        self.status = 200
        self.jwks_hits = 0
        self.disc_hits = 0


@pytest.fixture
def idp(keys: KeySet) -> Iterator[IdpState]:
    st = IdpState(keys)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_GET(self) -> None:
            if st.redirect_to:
                self.send_response(302)
                self.send_header("Location", st.redirect_to)
                self.end_headers()
                return
            if st.status != 200:
                self.send_response(st.status)
                self.end_headers()
                return
            if self.path == "/.well-known/openid-configuration":
                st.disc_hits += 1
                doc: dict[str, Any] = {
                    "issuer": st.disc_issuer_override or st.issuer,
                    "jwks_uri": f"{st.issuer}/jwks.json",
                }
            elif self.path == "/jwks.json":
                st.jwks_hits += 1
                doc = {"keys": st.jwks_keys}
            else:
                self.send_response(404)
                self.end_headers()
                return
            raw = json.dumps(doc).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    st.issuer = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield st
    finally:
        srv.shutdown()
        srv.server_close()


def _base_claims(issuer: str, **overrides: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "iss": issuer,
        "sub": "user-alice-123",
        "aud": "datagrant-cli",
        "iat": int(NOW - 30),
        "exp": int(NOW + 300),
        "email": "alice@example.com",
        "email_verified": True,
        "groups": ["idp-ml", "sec"],
    }
    c.update(overrides)
    return c


def _cfg(issuer: str, **overrides: Any) -> IdentityConfig:
    kw: dict[str, Any] = {
        "mode": "oidc",
        "issuer": issuer,
        "audience": ("datagrant-cli",),
    }
    kw.update(overrides)
    return IdentityConfig(**kw)


# ---------- valid RS256 / ES256 / EdDSA + token_sha256 ----------


@pytest.mark.parametrize("alg", ["RS256", "ES256", "EdDSA"])
def test_valid_algorithms_and_token_sha256(
    alg: str, idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    tok = keys.sign(_base_claims(idp.issuer), alg=alg)
    ident = verify_oidc_token(
        tok, _cfg(idp.issuer), now=NOW, cache_dir=tmp_path / "c", env=INSECURE_ENV
    )
    assert ident.username == "user-alice-123"
    assert ident.source == "oidc"
    assert ident.iss == idp.issuer
    assert ident.sub == "user-alice-123"
    assert ident.token_sha256 == hashlib.sha256(tok.encode("ascii")).hexdigest()
    assert ident.token_sha256 == token_sha256(tok)
    assert tok not in repr(ident)
    if os.name == "posix":
        cfiles = list((tmp_path / "c").glob("*.json"))
        assert len(cfiles) == 1 and (cfiles[0].stat().st_mode & 0o777) == 0o600


def test_email_claim_requires_boolean_verified(idp: IdpState, keys: KeySet, tmp_path: Path) -> None:
    cfg = _cfg(idp.issuer, username_claim="email")
    ok_tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    ident = verify_oidc_token(ok_tok, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)
    assert ident.username == "alice@example.com" and ident.sub == "user-alice-123"

    for bad_ver in (False, "true", 1, None):
        t = keys.sign(_base_claims(idp.issuer, email_verified=bad_ver), alg="EdDSA")
        with pytest.raises(IdentityError, match="email_verified"):
            verify_oidc_token(t, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)
    # Missing email_verified also fails closed.
    claims = _base_claims(idp.issuer)
    del claims["email_verified"]
    t2 = keys.sign(claims, alg="EdDSA")
    with pytest.raises(IdentityError, match="email_verified"):
        verify_oidc_token(t2, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


# ---------- time claims: exp, nbf, future iat, max_token_age, clock_skew ----------


def test_expired_future_nbf_future_iat_and_too_old(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    cfg = _cfg(idp.issuer)  # skew=60s, max_token_age=15m
    # Expired beyond 60s skew
    t_exp = keys.sign(_base_claims(idp.issuer, exp=int(NOW - 61)), alg="EdDSA")
    with pytest.raises(IdentityError, match="expired"):
        verify_oidc_token(t_exp, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)
    # Within 60s skew still passes
    t_skew = keys.sign(_base_claims(idp.issuer, exp=int(NOW - 30)), alg="EdDSA")
    assert verify_oidc_token(t_skew, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Future nbf beyond skew
    t_nbf = keys.sign(_base_claims(idp.issuer, nbf=int(NOW + 120)), alg="EdDSA")
    with pytest.raises(IdentityError, match="nbf"):
        verify_oidc_token(t_nbf, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Future iat beyond skew
    t_iat = keys.sign(_base_claims(idp.issuer, iat=int(NOW + 120)), alg="EdDSA")
    with pytest.raises(IdentityError, match="iat is in the future"):
        verify_oidc_token(t_iat, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Too old: valid exp, but iat older than default 15m + 60s skew
    t_old = keys.sign(
        _base_claims(idp.issuer, iat=int(NOW - 16 * 60 - 5), exp=int(NOW + 3600)), alg="EdDSA"
    )
    with pytest.raises(IdentityError, match="max_token_age"):
        verify_oidc_token(t_old, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


# ---------- iss / aud / azp ----------


def test_wrong_iss_and_aud_and_azp(idp: IdpState, keys: KeySet, tmp_path: Path) -> None:
    cfg = _cfg(idp.issuer)
    # Trailing slash mismatch on iss
    t_iss = keys.sign(_base_claims(idp.issuer + "/"), alg="EdDSA")
    with pytest.raises(IdentityError, match="iss"):
        verify_oidc_token(t_iss, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Wrong aud (string and list)
    for bad_aud in ("other-app", ["other-1", "other-2"]):
        t_aud = keys.sign(_base_claims(idp.issuer, aud=bad_aud), alg="EdDSA")
        with pytest.raises(IdentityError, match="aud"):
            verify_oidc_token(t_aud, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Multi-entry aud with matching entry passes unless azp is outside audience
    t_multi = keys.sign(
        _base_claims(idp.issuer, aud=["datagrant-cli", "other"], azp="datagrant-cli"), alg="EdDSA"
    )
    assert verify_oidc_token(t_multi, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    t_bad_azp = keys.sign(
        _base_claims(idp.issuer, aud=["datagrant-cli", "other"], azp="other"), alg="EdDSA"
    )
    with pytest.raises(IdentityError, match="azp"):
        verify_oidc_token(t_bad_azp, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


# ---------- alg none, HS256 w/ public key secret, key/alg confusion, forbidden headers ----------


def test_reject_alg_none_and_hs256_public_key_confusion(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    cfg = _cfg(idp.issuer)
    # alg: none (both 2-dot empty sig and non-empty sig)
    h_none = _b64u(b'{"alg":"none","kid":"rsa-1"}')
    p_b64 = _b64u(json.dumps(_base_claims(idp.issuer)).encode())
    for tok in (f"{h_none}.{p_b64}.", f"{h_none}.{p_b64}.AAAA"):
        with pytest.raises(IdentityError):
            verify_oidc_token(tok, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Classic HS256 signed with the RSA public key PEM bytes as HMAC secret
    pub_pem = keys.rsa_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    h_hs = _b64u(b'{"alg":"HS256","kid":"rsa-1"}')
    mac = hmac.new(pub_pem, f"{h_hs}.{p_b64}".encode("ascii"), hashlib.sha256).digest()
    hs_tok = f"{h_hs}.{p_b64}.{_b64u(mac)}"
    with pytest.raises(IdentityError, match="disallowed JWT alg"):
        verify_oidc_token(hs_tok, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Key-type mismatch: ES256 header pointing at RSA kid, and RS256 pointing at Ed25519 kid
    t_cross1 = keys.sign(_base_claims(idp.issuer), alg="ES256", kid="rsa-1")
    with pytest.raises(IdentityError, match="alg|ES256"):
        verify_oidc_token(t_cross1, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)
    t_cross2 = keys.sign(_base_claims(idp.issuer), alg="RS256", kid="ed-1")
    with pytest.raises(IdentityError, match="alg|RS256"):
        verify_oidc_token(t_cross2, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Tampered signature fails closed
    good = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    parts = good.split(".")
    flipped = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(IdentityError, match="signature|encoding"):
        verify_oidc_token(
            f"{parts[0]}.{parts[1]}.{flipped}", cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV
        )

    # Forbidden headers (jku, jwk, x5u, x5c, crit, zip) rejected
    for hdr in ("jku", "jwk", "x5u", "x5c", "crit", "zip"):
        bad = keys.sign(_base_claims(idp.issuer), extra_header={hdr: "https://evil.example"})
        with pytest.raises(IdentityError, match="forbidden JWT header"):
            verify_oidc_token(bad, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


# ---------- kid lookup, rotation refetch, rate-limit, cache TTL ----------


def test_kid_miss_refetches_once_rate_limited_and_cache_ttl(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    cfg = _cfg(idp.issuer)  # default 5m TTL
    cdir = tmp_path / "cache"
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    verify_oidc_token(tok, cfg, now=NOW, cache_dir=cdir, env=INSECURE_ENV)
    assert idp.jwks_hits == 1

    # Cached within TTL: even with server 503, cached key works without hitting network
    idp.status = 503
    verify_oidc_token(tok, cfg, now=NOW + 60, cache_dir=cdir, env=INSECURE_ENV)
    assert idp.jwks_hits == 1

    # Past 5m TTL with server down: fails closed
    with pytest.raises(IdentityError, match="HTTP 503"):
        verify_oidc_token(tok, cfg, now=NOW + 301, cache_dir=cdir, env=INSECURE_ENV)

    # Server back; rotate key with new kid: cache >=10s old triggers exactly one refetch
    idp.status = 200
    verify_oidc_token(tok, cfg, now=NOW + 310, cache_dir=cdir, env=INSECURE_ENV)
    hits_before = idp.jwks_hits

    rotated = ed25519.Ed25519PrivateKey.generate()
    rot_pub = rotated.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    idp.jwks_keys = [
        *idp.jwks_keys,
        {"kty": "OKP", "crv": "Ed25519", "kid": "ed-rotated", "alg": "EdDSA", "x": _b64u(rot_pub)},
    ]
    h_b64 = _b64u(b'{"alg":"EdDSA","kid":"ed-rotated"}')
    p_b64 = _b64u(
        json.dumps(_base_claims(idp.issuer, iat=int(NOW + 320), exp=int(NOW + 600))).encode()
    )
    rot_tok = f"{h_b64}.{p_b64}.{_b64u(rotated.sign(f'{h_b64}.{p_b64}'.encode()))}"

    # Within 10s rate-limit window: does NOT refetch, fails kid lookup
    with pytest.raises(IdentityError, match="no matching JWK"):
        verify_oidc_token(rot_tok, cfg, now=NOW + 315, cache_dir=cdir, env=INSECURE_ENV)
    assert idp.jwks_hits == hits_before

    # After 10s: refetches once and succeeds
    verify_oidc_token(rot_tok, cfg, now=NOW + 325, cache_dir=cdir, env=INSECURE_ENV)
    assert idp.jwks_hits == hits_before + 1

    # Unknown kid even after refetch: refetches once and fails
    miss_tok = keys.sign(
        _base_claims(idp.issuer, iat=int(NOW + 340), exp=int(NOW + 600)), kid="never-existed"
    )
    with pytest.raises(IdentityError, match="no matching JWK"):
        verify_oidc_token(miss_tok, cfg, now=NOW + 340, cache_dir=cdir, env=INSECURE_ENV)
    assert idp.jwks_hits == hits_before + 2


def test_duplicate_kid_fails_closed(idp: IdpState, keys: KeySet, tmp_path: Path) -> None:
    idp.jwks_keys = [idp.jwks_keys[2], dict(idp.jwks_keys[2])]  # two keys with kid='ed-1'
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    with pytest.raises(IdentityError, match="multiple keys share kid"):
        verify_oidc_token(tok, _cfg(idp.issuer), now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


# ---------- group_map trust boundary & allowed_groups ----------


def test_unmapped_same_named_idp_group_grants_nothing(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    # Caller's token has IdP groups ["ml", "sec"] matching policy.groups names,
    # and user "stranger" is NOT in static policy.groups. Without group_map, grants ZERO rights.
    pol_doc = {
        "version": 1,
        "approval": "two-person",
        "approvers": ["sec"],
        "max_duration": "4h",
        "groups": {"ml": ["alice"], "sec": ["carol"]},
        "identity": {
            "mode": "oidc",
            "issuer": idp.issuer,
            "audience": "datagrant-cli",
            "groups_claim": "groups",
        },
        "datasets": [
            {
                "name": "clinic",
                "database": "postgres",
                "tables": [
                    {
                        "name": "public.patients",
                        "allowed_groups": ["ml"],
                        "columns": {"id": "passthrough"},
                    }
                ],
            }
        ],
    }
    pol = parse_policy(pol_doc, env=INSECURE_ENV)
    tok = keys.sign(_base_claims(idp.issuer, sub="stranger", groups=["ml", "sec"]), alg="EdDSA")
    ident = verify_oidc_token(tok, pol.identity, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)
    assert ident.mapped_groups == frozenset()
    req = Request("stranger", "clinic", "public.patients", ("id",), timedelta(hours=1), "test")
    dec = evaluate(pol, req, extra_groups=ident.mapped_groups)
    assert not dec.allowed
    assert pol.can_approve("stranger", "alice", extra_groups=ident.mapped_groups) != []

    # With explicit group_map: only mapped IdP group grants the target policy group.
    pol_doc["identity"]["group_map"] = {"idp-ml": "ml"}
    pol_mapped = parse_policy(pol_doc, env=INSECURE_ENV)
    tok2 = keys.sign(
        _base_claims(idp.issuer, sub="stranger", groups=["idp-ml", "sec"]), alg="EdDSA"
    )
    ident2 = verify_oidc_token(
        tok2, pol_mapped.identity, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV
    )
    assert ident2.mapped_groups == frozenset({"ml"})
    assert evaluate(pol_mapped, req, extra_groups=ident2.mapped_groups).allowed
    # Still NOT an approver because "sec" was unmapped!
    assert pol_mapped.can_approve("stranger", "alice", extra_groups=ident2.mapped_groups) != []


def test_allowed_groups_gate(idp: IdpState, keys: KeySet, tmp_path: Path) -> None:
    cfg = _cfg(idp.issuer, groups_claim="groups", allowed_groups=frozenset({"contractors"}))
    tok = keys.sign(_base_claims(idp.issuer, groups=["eng"]), alg="EdDSA")
    with pytest.raises(IdentityError, match="allowed_groups"):
        verify_oidc_token(tok, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


# ---------- HTTPS enforcement, insecure localhost switch, redirects, discovery ----------


def test_insecure_localhost_requires_env_switch_and_warns_in_policy_check(
    idp: IdpState, keys: KeySet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    # Without env switch: verifier and policy parser both reject http://127.0.0.1
    with pytest.raises(IdentityError, match=INSECURE_LOCALHOST_ENV):
        verify_oidc_token(tok, _cfg(idp.issuer), now=NOW, cache_dir=tmp_path, env={})
    # Non-localhost http:// is ALWAYS rejected even with the switch set
    with pytest.raises(ValueError, match="https"):
        oidc.validate_oidc_url("http://idp.example.com", "issuer", allow_localhost_http=True)

    pol_file = tmp_path / "policy.yaml"
    pol_file.write_text(
        f"version: 1\nmax_duration: 1h\ngroups: {{g: [u]}}\n"
        f"identity:\n  mode: oidc\n  issuer: {idp.issuer}\n  audience: datagrant-cli\n"
        f"datasets:\n  - name: d\n    database: db\n    tables:\n"
        f"      - name: public.t\n        allowed_groups: [g]\n        columns: {{id: passthrough}}\n"
    )
    monkeypatch.delenv(INSECURE_LOCALHOST_ENV, raising=False)
    assert main(["policy", "check", str(pol_file)]) == 1
    monkeypatch.setenv(INSECURE_LOCALHOST_ENV, "1")
    out: list[str] = []
    assert main(["--json", "policy", "check", str(pol_file)], out.append) == EXIT_OK
    parsed = json.loads(out[-1])
    assert INSECURE_LOCALHOST_ENV in parsed["warnings"][0]
    assert INSECURE_LOCALHOST_ENV in capsys.readouterr().err


def test_redirect_and_discovery_mismatch_refused(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    idp.redirect_to = "https://evil.example/openid"
    with pytest.raises(IdentityError, match="redirect HTTP 302"):
        verify_oidc_token(
            tok, _cfg(idp.issuer), now=NOW, cache_dir=tmp_path / "c1", env=INSECURE_ENV
        )

    idp.redirect_to = None
    idp.disc_issuer_override = "https://wrong.example"
    with pytest.raises(IdentityError, match="discovery issuer mismatch"):
        verify_oidc_token(
            tok, _cfg(idp.issuer), now=NOW, cache_dir=tmp_path / "c2", env=INSECURE_ENV
        )


# ---------- policy.identity validation, token file safety & token redaction ----------


@pytest.mark.parametrize(
    "ident_block",
    [
        {"mode": "local", "issuer": "https://idp.example.com"},
        {"mode": "oidc", "issuer": "https://idp.example.com"},  # missing audience
        {"mode": "oidc", "issuer": "https://u:p@idp.example.com", "audience": "a"},
        {"mode": "oidc", "issuer": "https://idp.example.com?x=1", "audience": "a"},
        {
            "mode": "oidc",
            "issuer": "https://idp.example.com",
            "audience": "a",
            "algorithms": ["HS256"],
        },
        {
            "mode": "oidc",
            "issuer": "https://idp.example.com",
            "audience": "a",
            "algorithms": ["none"],
        },
        {
            "mode": "oidc",
            "issuer": "https://idp.example.com",
            "audience": "a",
            "group_map": {"x": "ml"},
        },
        {
            "mode": "oidc",
            "issuer": "https://idp.example.com",
            "audience": "a",
            "groups_claim": "groups",
            "group_map": {"x": "nonexistent"},
        },
        {"mode": "oidc", "issuer": "https://idp.example.com", "audience": "a", "unknown": 1},
    ],
)
def test_invalid_policy_identity_blocks(ident_block: dict[str, Any]) -> None:
    doc = {
        "version": 1,
        "max_duration": "1h",
        "groups": {"ml": ["alice"]},
        "identity": ident_block,
        "datasets": [
            {
                "name": "d",
                "database": "db",
                "tables": [
                    {"name": "public.t", "allowed_groups": ["ml"], "columns": {"id": "passthrough"}}
                ],
            }
        ],
    }
    with pytest.raises(PolicyError):
        parse_policy(doc)


def test_token_file_rules_and_never_logged(idp: IdpState, keys: KeySet, tmp_path: Path) -> None:
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    tf = tmp_path / "tok"
    tf.write_text(tok + "\n")
    tf.chmod(0o600)
    assert read_token_file(tf) == tok

    with pytest.raises(IdentityError, match="stdin"):
        read_token_file("-")

    if sys.platform != "win32":
        loose = tmp_path / "loose"
        loose.write_text(tok)
        loose.chmod(0o644)
        with pytest.raises(IdentityError) as ei:
            read_token_file(loose)
        assert tok not in str(ei.value)

        link = tmp_path / "link"
        link.symlink_to(tf)
        with pytest.raises(IdentityError) as ei2:
            read_token_file(link)
        assert tok not in str(ei2.value)

    # Error messages on bad tokens never contain the raw token
    bad_tok = keys.sign(_base_claims(idp.issuer, aud="wrong-aud"), alg="EdDSA")
    with pytest.raises(IdentityError) as ei3:
        verify_oidc_token(bad_tok, _cfg(idp.issuer), now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)
    assert bad_tok not in str(ei3.value)
    assert bad_tok.split(".")[2] not in str(ei3.value)
    assert redact_token(f"err with {bad_tok} inside", bad_tok) == "err with *** inside"


def test_jws_jwk_and_claim_edge_cases(idp: IdpState, keys: KeySet, tmp_path: Path) -> None:
    cfg = _cfg(idp.issuer, jwks_cache_ttl=timedelta(seconds=0))
    # Default cache dir helper with env override and default
    assert oidc.default_cache_dir({oidc.JWKS_CACHE_DIR_ENV: str(tmp_path / "x")}) == tmp_path / "x"
    assert oidc.default_cache_dir({}).name == "jwks"
    assert redact_token("unchanged", None) == "unchanged"

    # Non-oidc config rejected by verify_oidc_token
    with pytest.raises(IdentityError, match="non-oidc"):
        verify_oidc_token("a.b.c", IdentityConfig())

    # Empty, whitespace, non-3-part, bad base64url, non-JSON, non-dict header/payload
    for bad in ("", "has space.a.b", "only.two", "a.b.c.d", "!.a.b", "YQ.YQ.YQ"):
        with pytest.raises(IdentityError):
            verify_oidc_token(bad, cfg, now=NOW, env=INSECURE_ENV)
    arr = _b64u(b"[1,2]")
    with pytest.raises(IdentityError, match="JSON objects"):
        verify_oidc_token(f"{arr}.{arr}.AAAA", cfg, now=NOW, env=INSECURE_ENV)
    no_kid = _b64u(b'{"alg":"EdDSA"}')
    pay = _b64u(json.dumps(_base_claims(idp.issuer)).encode())
    with pytest.raises(IdentityError, match="kid"):
        verify_oidc_token(f"{no_kid}.{pay}.AAAA", cfg, now=NOW, env=INSECURE_ENV)

    # Boolean timestamp / missing exp / bad groups claim type / missing sub
    for bad_claims in (
        _base_claims(idp.issuer, exp=True),
        {k: v for k, v in _base_claims(idp.issuer).items() if k != "exp"},
        _base_claims(idp.issuer, sub=""),
        _base_claims(idp.issuer, aud=123),
        _base_claims(idp.issuer, groups="not-a-list"),
    ):
        t = keys.sign(bad_claims, alg="EdDSA")
        with pytest.raises(IdentityError):
            verify_oidc_token(
                t,
                _cfg(idp.issuer, groups_claim="groups", jwks_cache_ttl=timedelta(seconds=0)),
                now=NOW,
                env=INSECURE_ENV,
            )

    # RSA <2048 bits rejected
    small_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    sn = small_rsa.public_key().public_numbers()
    idp.jwks_keys = [
        {"kty": "RSA", "kid": "small", "alg": "RS256", "n": _int_b64u(sn.n), "e": _int_b64u(sn.e)}
    ]
    h_s = _b64u(b'{"alg":"RS256","kid":"small"}')
    sig_s = small_rsa.sign(f"{h_s}.{pay}".encode(), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(IdentityError, match="2048"):
        verify_oidc_token(f"{h_s}.{pay}.{_b64u(sig_s)}", cfg, now=NOW, env=INSECURE_ENV)

    # Token file oversized / directory / missing
    big = tmp_path / "big"
    big.write_bytes(b"a" * (oidc.MAX_TOKEN_BYTES + 10))
    big.chmod(0o600)
    with pytest.raises(IdentityError, match="exceeds"):
        read_token_file(big)
    with pytest.raises(IdentityError, match="regular file|cannot open"):
        read_token_file(tmp_path)
    with pytest.raises(IdentityError, match="cannot open"):
        read_token_file(tmp_path / "missing")


def test_slow_trickle_idp_hits_deadline(keys: KeySet, tmp_path: Path) -> None:
    stop = threading.Event()

    class Slow(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            for _ in range(1000):
                if stop.is_set():
                    return
                try:
                    self.wfile.write(b"{")
                    self.wfile.flush()
                except OSError:
                    return
                threading.Event().wait(0.2)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        issuer = f"http://127.0.0.1:{srv.server_address[1]}"
        tok = keys.sign(_base_claims(issuer), alg="EdDSA")
        with pytest.raises(IdentityError, match="timed out"):
            verify_oidc_token(
                tok, _cfg(issuer), now=NOW, cache_dir=tmp_path, env=INSECURE_ENV, timeout=0.8
            )
    finally:
        stop.set()
        srv.shutdown()
        srv.server_close()


# ---------- QE + Red Team review regression tests ----------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions, symlinks and uids")
def test_cache_dir_no_chmod_existing_and_lstat_fstat_checks(
    idp: IdpState, keys: KeySet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    cfg = _cfg(idp.issuer)

    # QE1: existing loose directory (0755) is NOT silently chmodded; fails closed
    loose_dir = tmp_path / "loose_dir"
    loose_dir.mkdir()
    loose_dir.chmod(0o755)
    with pytest.raises(IdentityError, match="group/others"):
        verify_oidc_token(tok, cfg, now=NOW, cache_dir=loose_dir, env=INSECURE_ENV)
    assert (loose_dir.stat().st_mode & 0o777) == 0o755

    # L7: symlinked cache directory rejected
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir(mode=0o700)
    real_dir.chmod(0o700)
    sym_dir = tmp_path / "sym_dir"
    sym_dir.symlink_to(real_dir)
    with pytest.raises(IdentityError, match="symlink"):
        verify_oidc_token(tok, cfg, now=NOW, cache_dir=sym_dir, env=INSECURE_ENV)

    # L7: non-directory path rejected
    file_path = tmp_path / "not_a_dir"
    file_path.write_text("x")
    file_path.chmod(0o600)
    with pytest.raises(IdentityError, match="not a directory"):
        verify_oidc_token(tok, cfg, now=NOW, cache_dir=file_path, env=INSECURE_ENV)

    # L7: cache directory owned by a different uid rejected
    other_dir = tmp_path / "other_uid_dir"
    other_dir.mkdir(mode=0o700)
    other_dir.chmod(0o700)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(other_dir).st_uid + 1)
    with pytest.raises(IdentityError, match="not owned by current uid"):
        verify_oidc_token(tok, cfg, now=NOW, cache_dir=other_dir, env=INSECURE_ENV)
    monkeypatch.undo()

    # L7: cache file owned by a different uid rejected on read
    good_dir = tmp_path / "good_dir"
    verify_oidc_token(tok, cfg, now=NOW, cache_dir=good_dir, env=INSECURE_ENV)
    cfile = next(good_dir.glob("*.json"))
    orig_fstat = os.fstat
    target_ino = cfile.stat().st_ino

    class FakeStat:
        def __init__(self, st: os.stat_result) -> None:
            self._st = st
            self.st_uid = st.st_uid + 99

        def __getattr__(self, name: str) -> Any:
            return getattr(self._st, name)

    def fake_fstat(fd: int) -> Any:
        st = orig_fstat(fd)
        return FakeStat(st) if st.st_ino == target_ino else st

    monkeypatch.setattr(os, "fstat", fake_fstat)
    with pytest.raises(IdentityError, match="not owned by current uid"):
        verify_oidc_token(tok, cfg, now=NOW + 1, cache_dir=good_dir, env=INSECURE_ENV)


def test_cache_write_oserror_wrapped_and_skipped_after_good_fetch(
    idp: IdpState, keys: KeySet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    cdir = tmp_path / "ro_cache"

    # QE2: OSError from mkstemp in _write_cache is wrapped in IdentityError,
    # and _resolve_jwk skips caching after a good fetch so verification still succeeds!
    def boom_mkstemp(*a: Any, **kw: Any) -> tuple[int, str]:
        raise PermissionError(13, "Read-only file system")

    monkeypatch.setattr("datagrant.oidc.tempfile.mkstemp", boom_mkstemp)
    with pytest.raises(IdentityError, match="cannot create temporary JWKS cache"):
        oidc._write_cache(cdir / "x.json", {"a": 1})

    ident = verify_oidc_token(tok, _cfg(idp.issuer), now=NOW, cache_dir=cdir, env=INSECURE_ENV)
    assert ident.username == "user-alice-123"
    assert list(cdir.glob("*.json")) == []


def test_jws_like_path_anchor_allows_dotted_directories() -> None:
    # Anchored (?<![A-Za-z0-9_-]): normal dotted directory segments are NOT misclassified
    normal = Path("/home/alice/my.config.directory/oidc-token")
    assert oidc._safe_path_label(normal) == str(normal)
    # A path segment that itself has 3 base64url parts IS redacted
    fake_jws = ".".join([_b64u(b'{"alg":"EdDSA"}'), _b64u(b'{"sub":"alice"}'), _b64u(b"signature")])
    pasted = Path(f"/tmp/{fake_jws}")
    assert oidc._safe_path_label(pasted) == "<redacted token-like path>"


def test_cli_oidc_end_to_end_flows_receipts_and_mode_mismatch(
    idp: IdpState, keys: KeySet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from datetime import UTC, datetime

    from datagrant import cli as cli_mod
    from datagrant import receipt as receipt_mod
    from datagrant.keys import load_signing_key
    from datagrant.pg import grant as g_mod
    from datagrant.pg import requests as rq_mod
    from datagrant.pg.mask import ColumnType, TableCatalog

    monkeypatch.setenv(INSECURE_LOCALHOST_ENV, "1")
    monkeypatch.setenv(oidc.JWKS_CACHE_DIR_ENV, str(tmp_path / "jwks_cache"))
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:5432/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "keys" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "keys" / "signing.key"))
    log_path = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(log_path))
    monkeypatch.delenv(oidc.OIDC_TOKEN_ENV, raising=False)
    assert main(["keys", "init", "--apply"], lambda s: None) == EXIT_OK

    cat = TableCatalog(
        {"id": ColumnType("pg_catalog", "int4"), "ssn": ColumnType("pg_catalog", "text")},
        "public",
    )

    class StubConn:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    stored_reqs: dict[str, rq_mod.PendingRequest] = {}
    t_now = datetime(2026, 11, 5, 18, tzinfo=UTC)

    def stub_create(conn: Any, req: Request, **kw: Any) -> rq_mod.PendingRequest:
        rid = f"req{len(stored_reqs) + 1:09d}"
        pr = rq_mod.PendingRequest(
            rid,
            req,
            kw["policy_sha256"],
            kw["verifier"],
            t_now,
            t_now + kw["ttl"],
            "pending",
            None,
            None,
            dict(kw["requester_identity"]) if kw.get("requester_identity") else None,
        )
        stored_reqs[rid] = pr
        return pr

    def stub_apply(conn: Any, plan: g_mod.GrantPlan, sink: g_mod.ReceiptSink, **kw: Any) -> None:
        assert plan.facts is not None
        receipt_mod.append(sink.log, "issued", plan.facts, sink.key, host="test-host")

    monkeypatch.setattr(cli_mod, "_connect", lambda a: StubConn())
    monkeypatch.setattr(g_mod, "ensure_state", lambda c: [])
    monkeypatch.setattr("datagrant.pg.mask.inspect_table", lambda c, t: cat)
    monkeypatch.setattr(rq_mod, "create_request", stub_create)
    monkeypatch.setattr(rq_mod, "get_request", lambda c, rid: stored_reqs[rid])
    monkeypatch.setattr(g_mod, "apply_plan", stub_apply)

    oidc_two = tmp_path / "oidc-two.yaml"
    oidc_two.write_text(
        f"version: 1\napproval: two-person\napprovers: [sec]\nmax_duration: 4h\n"
        f"groups: {{ml: [], sec: []}}\n"
        f"identity:\n  mode: oidc\n  issuer: {idp.issuer}\n  audience: datagrant-cli\n"
        f"  username_claim: email\n  groups_claim: groups\n"
        f"  group_map: {{idp-ml: ml, idp-sec: sec}}\n"
        f"datasets:\n  - name: clinic\n    database: clinicdb\n    tables:\n"
        f"      - name: public.p\n        allowed_groups: [ml]\n"
        f"        columns: {{id: passthrough, ssn: hash}}\n"
    )
    local_two = tmp_path / "local-two.yaml"
    local_two.write_text(
        "version: 1\napproval: two-person\napprovers: [sec]\nmax_duration: 4h\n"
        "groups: {ml: [alice@example.com], sec: [carol@example.com]}\n"
        "datasets:\n  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.p\n        allowed_groups: [ml]\n"
        "        columns: {id: passthrough, ssn: hash}\n"
    )

    req_args = [
        "--dataset",
        "clinic",
        "--table",
        "public.p",
        "--columns",
        "id,ssn",
        "--duration",
        "1h",
        "--purpose",
        "audit-test",
    ]
    now_ts = int(time.time())

    # 1. --as-user in oidc mode -> exit 2 before network/DB
    out: list[str] = []
    rc = main(
        ["--json", "request", "--policy", str(oidc_two), "--as-user", "alice", *req_args],
        out.append,
    )
    assert rc == 2 and "--as-user" in json.loads(out[-1])["error"]

    # 2. Missing token in oidc mode -> exit 2
    out.clear()
    rc = main(["--json", "request", "--policy", str(oidc_two), *req_args], out.append)
    assert rc == 2 and "no OIDC token" in json.loads(out[-1])["error"]

    # 3. --oidc-token-file in local mode -> exit 2
    tf_alice = tmp_path / "alice.jwt"
    alice_tok = keys.sign(
        _base_claims(
            idp.issuer,
            sub="sub-alice-1",
            email="alice@example.com",
            groups=["idp-ml"],
            iat=now_ts - 5,
            exp=now_ts + 300,
        ),
        alg="EdDSA",
    )
    tf_alice.write_text(alice_tok + "\n")
    tf_alice.chmod(0o600)
    out.clear()
    rc = main(
        [
            "--json",
            "request",
            "--policy",
            str(local_two),
            "--oidc-token-file",
            str(tf_alice),
            *req_args,
        ],
        out.append,
    )
    assert rc == 2 and "local" in json.loads(out[-1])["error"]

    # 4. Invalid/expired token -> exit 1 and raw token never in output
    exp_tok = keys.sign(_base_claims(idp.issuer, iat=now_ts - 600, exp=now_ts - 300), alg="EdDSA")
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, exp_tok)
    out.clear()
    rc = main(["--json", "request", "--policy", str(oidc_two), *req_args], out.append)
    assert rc == 1 and exp_tok not in out[-1]
    monkeypatch.delenv(oidc.OIDC_TOKEN_ENV, raising=False)

    # 5. Valid OIDC request via --oidc-token-file creates pending request with mode+iss+sub
    out.clear()
    rc = main(
        [
            "--json",
            "request",
            "--apply",
            "--policy",
            str(oidc_two),
            "--oidc-token-file",
            str(tf_alice),
            *req_args,
        ],
        out.append,
    )
    p_resp = json.loads(out[-1])
    assert rc == 0 and p_resp["status"] == "pending" and p_resp["identity_source"] == "oidc"
    assert alice_tok not in out[-1]
    rid = p_resp["request_id"]
    assert stored_reqs[rid].requester_identity == {
        "mode": "oidc",
        "source": "oidc",
        "iss": idp.issuer,
        "sub": "sub-alice-1",
        "token_sha256": token_sha256(alice_tok),
        "username_claim": "email",
        "groups_claim": "groups",
        "idp_groups": ["idp-ml"],
    }

    # 6. Mode mismatch: approving OIDC request under local policy refuses exit 1 (no fallback)
    out.clear()
    rc = main(
        [
            "--json",
            "approve",
            "--apply",
            "--policy",
            str(local_two),
            "--as-user",
            "carol@example.com",
            rid,
        ],
        out.append,
    )
    assert rc == 1 and "identity mode" in json.loads(out[-1])["error"]

    # And vice versa: local pending request approved under OIDC policy refuses exit 1
    out.clear()
    assert (
        main(
            [
                "--json",
                "request",
                "--apply",
                "--policy",
                str(local_two),
                "--as-user",
                "alice@example.com",
                *req_args,
            ],
            out.append,
        )
        == 0
    )
    local_rid = json.loads(out[-1])["request_id"]
    carol_tok = keys.sign(
        _base_claims(
            idp.issuer,
            sub="sub-carol-2",
            email="carol@example.com",
            groups=["idp-sec"],
            iat=now_ts - 5,
            exp=now_ts + 300,
        ),
        alg="RS256",
    )
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, carol_tok)
    out.clear()
    rc = main(["--json", "approve", "--apply", "--policy", str(oidc_two), local_rid], out.append)
    assert rc == 1 and "identity mode" in json.loads(out[-1])["error"]

    # 7. Self-approval blocked by (iss, sub) EVEN if mutable email claim changed!
    alice_renamed_tok = keys.sign(
        _base_claims(
            idp.issuer,
            sub="sub-alice-1",  # SAME sub as requester!
            email="alice-new-alias@example.com",
            groups=["idp-sec"],
            iat=now_ts - 5,
            exp=now_ts + 300,
        ),
        alg="EdDSA",
    )
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, alice_renamed_tok)
    out.clear()
    rc = main(["--json", "approve", "--apply", "--policy", str(oidc_two), rid], out.append)
    assert rc == 1 and "different person" in json.dumps(json.loads(out[-1])["reasons"])

    # 8. Unmapped same-named IdP group "sec" on eve's token does NOT grant approver rights
    eve_unmapped = keys.sign(
        _base_claims(
            idp.issuer,
            sub="sub-eve-3",
            email="eve@example.com",
            groups=["sec"],  # matches policy group name, NOT in group_map!
            iat=now_ts - 5,
            exp=now_ts + 300,
        ),
        alg="EdDSA",
    )
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, eve_unmapped)
    out.clear()
    rc = main(["--json", "approve", "--apply", "--policy", str(oidc_two), rid], out.append)
    assert rc == 1 and "not in an approver group" in json.dumps(json.loads(out[-1])["reasons"])

    # 9. Valid OIDC approval by carol (via group_map idp-sec -> sec) writes receipt with token_sha256 only
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, carol_tok)
    out.clear()
    rc = main(["--json", "approve", "--apply", "--policy", str(oidc_two), rid], out.append)
    assert rc == 0 and json.loads(out[-1])["status"] == "granted"
    assert carol_tok not in out[-1] and alice_tok not in out[-1]

    # Prepend a legacy v0.2.0 receipt (no identity / approver_identities fields) and verify chain!
    skey = load_signing_key(tmp_path / "keys" / "signing.key")
    raw_log_text = log_path.read_text()
    assert alice_tok not in raw_log_text and carol_tok not in raw_log_text
    rec_body = json.loads(raw_log_text.splitlines()[0])["receipt"]
    assert rec_body["identity"] == {
        "source": "oidc",
        "iss": idp.issuer,
        "sub": "sub-alice-1",
        "token_sha256": token_sha256(alice_tok),
    }
    assert rec_body["approver_identities"] == [
        {
            "approver": "carol@example.com",
            "source": "oidc",
            "iss": idp.issuer,
            "sub": "sub-carol-2",
            "token_sha256": token_sha256(carol_tok),
        }
    ]
    assert receipt_mod.verify(log_path, skey.private.public_key()).ok
    capsys.readouterr()


def test_strict_json_nan_infinity_duplicate_keys_and_deep_nesting(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    cfg = _cfg(idp.issuer, jwks_cache_ttl=timedelta(seconds=0))

    # M2: NaN / Infinity in JWT payload and non-finite `now` rejected
    for raw_const in ("NaN", "Infinity", "-Infinity"):
        h = _b64u(b'{"alg":"EdDSA","kid":"ed-1"}')
        p = _b64u(
            f'{{"iss":"{idp.issuer}","sub":"u","aud":"datagrant-cli","iat":1800000000,"exp":{raw_const}}}'.encode()
        )
        sig = keys.ed_priv.sign(f"{h}.{p}".encode("ascii"))
        with pytest.raises(IdentityError, match="non-standard JSON constant"):
            verify_oidc_token(f"{h}.{p}.{_b64u(sig)}", cfg, now=NOW, env=INSECURE_ENV)

    good = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    with pytest.raises(IdentityError, match="non-finite"):
        verify_oidc_token(good, cfg, now=float("nan"), env=INSECURE_ENV)
    with pytest.raises(IdentityError, match="non-finite"):
        verify_oidc_token(good, cfg, now=float("inf"), env=INSECURE_ENV)

    # L4: duplicate JSON keys rejected in JWT header, JWT payload, HTTP response, and cache
    dup_hdr = _b64u(b'{"alg":"RS256","alg":"EdDSA","kid":"ed-1"}')
    pay = _b64u(json.dumps(_base_claims(idp.issuer)).encode())
    sig = keys.ed_priv.sign(f"{dup_hdr}.{pay}".encode("ascii"))
    with pytest.raises(IdentityError, match="duplicate JSON key"):
        verify_oidc_token(f"{dup_hdr}.{pay}.{_b64u(sig)}", cfg, now=NOW, env=INSECURE_ENV)

    dup_pay = _b64u(
        f'{{"iss":"{idp.issuer}","sub":"victim","sub":"attacker","aud":"datagrant-cli","iat":1800000000,"exp":1800000300}}'.encode()
    )
    h_ok = _b64u(b'{"alg":"EdDSA","kid":"ed-1"}')
    sig2 = keys.ed_priv.sign(f"{h_ok}.{dup_pay}".encode("ascii"))
    with pytest.raises(IdentityError, match="duplicate JSON key"):
        verify_oidc_token(f"{h_ok}.{dup_pay}.{_b64u(sig2)}", cfg, now=NOW, env=INSECURE_ENV)

    with pytest.raises(IdentityError, match="duplicate JSON key"):
        oidc._strict_json_loads(b'{"keys":[],"keys":[]}', "JWKS")

    # L5: deep nesting -> IdentityError on token/endpoint, None on cache read
    deep = b"[" * 2000 + b"]" * 2000
    with pytest.raises(IdentityError, match="nested too deeply"):
        oidc._strict_json_loads(deep, "JWT payload")
    cdir = tmp_path / "deep_cache"
    cdir.mkdir(mode=0o700)
    if os.name == "posix":
        cdir.chmod(0o700)
    cfile = cdir / "bad.json"
    cfile.write_bytes(b'{"a":' * 100 + b"1" + b"}" * 100)
    if os.name == "posix":
        cfile.chmod(0o600)
    assert oidc._read_cache(cfile) is None


def test_azp_required_for_multi_aud_and_validated_for_single_aud(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    cfg = _cfg(idp.issuer)
    # M3: multi-aud WITHOUT azp is rejected
    t_no_azp = keys.sign(_base_claims(idp.issuer, aud=["datagrant-cli", "other"]), alg="EdDSA")
    with pytest.raises(IdentityError, match="multiple audiences must include azp"):
        verify_oidc_token(t_no_azp, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)

    # Single-aud WITH disallowed or non-string azp is also rejected
    for bad_azp in ("evil-client", 123, None):
        t_single = keys.sign(
            _base_claims(idp.issuer, aud="datagrant-cli", azp=bad_azp), alg="EdDSA"
        )
        with pytest.raises(IdentityError, match="azp"):
            verify_oidc_token(t_single, cfg, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV)


def test_jws_like_token_file_path_not_echoed_and_cli_hides_oidc_token(
    idp: IdpState, keys: KeySet, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant import cli as cli_mod

    # L6: accidentally passing a raw JWS as the file path to read_token_file never echoes it
    tok = keys.sign(_base_claims(idp.issuer), alg="EdDSA")
    with pytest.raises(IdentityError) as ei:
        read_token_file(tok)
    assert tok not in str(ei.value)
    assert tok.split(".")[1] not in str(ei.value)
    assert "<redacted token-like path>" in str(ei.value)

    # cli._hide_token also scrubs $DATAGRANT_OIDC_TOKEN
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, tok)
    assert tok not in cli_mod._hide_token(f"boom: {tok}")


def test_recursion_error_from_json_loads_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **kw: Any) -> Any:
        raise RecursionError("max recursion")

    monkeypatch.setattr("datagrant.oidc.json.loads", boom)
    with pytest.raises(IdentityError, match="nested too deeply"):
        oidc._strict_json_loads(b"{}", "JWT payload")


def test_url_b64u_jwk_and_http_error_branches(
    idp: IdpState, keys: KeySet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # validate_oidc_url error branches
    for bad_url in ("", "https://h:notaport", "https:///nohost", "ftp://idp.example"):
        with pytest.raises(ValueError):
            oidc.validate_oidc_url(bad_url, "u")

    # _b64u_decode / _b64u_uint error branches
    with pytest.raises(IdentityError, match="length"):
        oidc._b64u_decode("abcde", "seg")  # len % 4 == 1
    with pytest.raises(IdentityError, match="non-canonical"):
        oidc._b64u_decode("AB", "seg")  # non-zero trailing bits
    with pytest.raises(IdentityError, match="base64url string"):
        oidc._b64u_uint(123, "n")
    with pytest.raises(IdentityError, match="leading zero"):
        oidc._b64u_uint(_b64u(b"\x00\x01"), "n")

    # read_token_file non-ASCII and whitespace-only
    na = tmp_path / "nonascii"
    na.write_bytes(b"\xff\xfe")
    na.chmod(0o600)
    with pytest.raises(IdentityError, match="not ASCII"):
        read_token_file(na)
    ws = tmp_path / "ws"
    ws.write_text("   \n")
    ws.chmod(0o600)
    with pytest.raises(IdentityError, match="compact JWT"):
        read_token_file(ws)

    # JWK signature material errors (even RSA exponent, short EC/EdDSA sig/coords, key_ops filter)
    for jwk_entry, alg, sig_bytes in [
        ({"kty": "RSA", "kid": "k1", "n": "AQAB", "e": _int_b64u(4)}, "RS256", b"x" * 256),
        ({"kty": "EC", "crv": "P-384", "kid": "k1", "x": "AA", "y": "AA"}, "ES256", b"x" * 64),
        ({"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}, "ES256", b"short"),
        ({"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}, "ES256", b"x" * 64),
        ({"kty": "OKP", "crv": "X25519", "kid": "k1", "x": "AA"}, "EdDSA", b"x" * 64),
        ({"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": "AA"}, "EdDSA", b"short"),
        ({"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": "AA"}, "EdDSA", b"x" * 64),
    ]:
        with pytest.raises(IdentityError):
            oidc._verify_jws_signature(alg, jwk_entry, b"a.b", sig_bytes)

    assert oidc._usable_jwks_entries([{"kty": "OKP", "key_ops": ["sign"]}]) == []
    with pytest.raises(IdentityError):
        oidc._usable_jwks_entries("not-a-list")
    with pytest.raises(IdentityError):
        oidc._usable_jwks_entries(["not-a-dict"])

    # Corrupt / oversized cache file returns None cleanly (cross-platform)
    cdir = tmp_path / "corrupt_cache"
    cdir.mkdir(mode=0o700)
    if sys.platform != "win32":
        cdir.chmod(0o700)
    cf = cdir / "c.json"
    cf.write_text("not json")
    if sys.platform != "win32":
        cf.chmod(0o600)
    assert oidc._read_cache(cf) is None
    cf.write_text('{"fetched_at": "bad"}')
    assert oidc._read_cache(cf) is None
    cf.write_bytes(b"x" * (oidc.MAX_HTTP_BYTES * 2 + 10))
    assert oidc._read_cache(cf) is None

    # Cache write failure on os.replace is wrapped in IdentityError and cleans up temp file
    monkeypatch.setattr(
        "datagrant.oidc.os.replace",
        lambda *a: (_ for _ in ()).throw(OSError(13, "denied")),
    )
    with pytest.raises(IdentityError, match="cannot write JWKS cache"):
        oidc._write_cache(cdir / "out.json", {"k": 1})
    assert list(cdir.glob(".jwks.*")) == []


def test_legacy_receipts_and_new_oidc_receipts_verify_together_and_forbid_raw_tokens(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime, timedelta

    from datagrant import receipt as receipt_mod
    from datagrant.keys import init_keys, load_signing_key
    from datagrant.receipt import GrantFacts, ReceiptError

    _, sp, _ = init_keys(tmp_path / "k")
    skey = load_signing_key(sp)
    t0 = datetime(2026, 11, 5, 18, tzinfo=UTC)
    log = tmp_path / "mixed.jsonl"

    # seq 0: legacy v0.2.0 receipt without identity / approver_identities
    legacy = GrantFacts(
        "000000000001",
        "alice",
        "clinic",
        "public.p",
        ("id",),
        {"id": "passthrough"},
        None,
        "legacy",
        t0,
        t0 + timedelta(hours=1),
        "a" * 64,
        1,
        "auto",
    )
    b0 = receipt_mod.append(log, "issued", legacy, skey, event_at=t0, host="h")
    assert "identity" not in b0 and "approver_identities" not in b0

    # seq 1: v0.3.0 OIDC receipt with identity + approver_identities (token_sha256 only)
    modern = GrantFacts(
        "000000000002",
        "alice@example.com",
        "clinic",
        "public.p",
        ("id",),
        {"id": "passthrough"},
        None,
        "oidc",
        t0,
        t0 + timedelta(hours=1),
        "b" * 64,
        1,
        "two-person",
        ("carol@example.com",),
        {"source": "oidc", "iss": "https://idp.example.com", "sub": "u1", "token_sha256": "c" * 64},
        (
            {
                "approver": "carol@example.com",
                "source": "oidc",
                "iss": "https://idp.example.com",
                "sub": "u2",
                "token_sha256": "d" * 64,
            },
        ),
    )
    b1 = receipt_mod.append(log, "issued", modern, skey, event_at=t0, host="h")
    assert b1["identity"]["token_sha256"] == "c" * 64
    res = receipt_mod.verify(log, skey.private.public_key())
    assert res.ok and res.count == 2

    # Forbidden raw-token key names rejected by canonical()
    for bad_key in ("token", "id_token", "oidc_token", "access_token"):
        with pytest.raises(ReceiptError, match="secrets"):
            receipt_mod.canonical({"identity": {bad_key: "secret"}})


def test_red_team_pr28_m1_l2_l3_regressions(
    idp: IdpState, keys: KeySet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from datetime import UTC, datetime

    from datagrant import cli as cli_mod
    from datagrant.pg import grant as g_mod
    from datagrant.pg import requests as rq_mod
    from datagrant.pg.mask import ColumnType, TableCatalog

    monkeypatch.setenv(INSECURE_LOCALHOST_ENV, "1")
    monkeypatch.setenv(oidc.JWKS_CACHE_DIR_ENV, str(tmp_path / "jc"))
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw9secret@db.example:5432/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
    assert main(["keys", "init", "--apply"], lambda s: None) == EXIT_OK

    # L2: email-style usernames are lowercased in verify_oidc_token AND casefold-compared in can_approve
    mixed_tok = keys.sign(
        _base_claims(idp.issuer, sub="sub-mixed", email="Alice.User@Example.COM"),
        alg="EdDSA",
    )
    v_email = verify_oidc_token(
        mixed_tok,
        _cfg(idp.issuer, username_claim="email"),
        now=NOW,
        cache_dir=tmp_path / "jc",
        env=INSECURE_ENV,
    )
    assert v_email.username == "alice.user@example.com"

    # Also email-shaped sub / preferred_username is lowercased
    mixed_upn = keys.sign(
        _base_claims(idp.issuer, sub="Alice@Example.COM"),
        alg="EdDSA",
    )
    v_sub = verify_oidc_token(
        mixed_upn,
        _cfg(idp.issuer, username_claim="sub"),
        now=NOW,
        cache_dir=tmp_path / "jc",
        env=INSECURE_ENV,
    )
    assert v_sub.username == "alice@example.com"

    # Local policy can_approve blocks Alice@ vs alice@ via casefold
    local_pol = parse_policy(
        {
            "version": 1,
            "approval": "two-person",
            "approvers": ["sec"],
            "max_duration": "1h",
            "groups": {"ml": ["alice@example.com"], "sec": ["alice@example.com"]},
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        }
    )
    assert any(
        "different person" in r
        for r in local_pol.can_approve("Alice@Example.COM", "alice@example.com")
    )

    # L3: allow_abbrev=False rejects --oidc-token=... (will NOT prefix-match --oidc-token-file!)
    # AND _SafeArgumentParser.error scrubs any JWS / $DATAGRANT_OIDC_TOKEN from usage stderr!
    now_ts = int(time.time())
    live_tok = keys.sign(_base_claims(idp.issuer, iat=now_ts - 5, exp=now_ts + 300), alg="EdDSA")
    capsys.readouterr()
    rc_abb = main(
        [
            "request",
            "--dataset",
            "d",
            "--table",
            "s.t",
            "--columns",
            "id",
            "--duration",
            "1h",
            "--purpose",
            "p",
            f"--oidc-token={live_tok}",
        ]
    )
    err_abb = capsys.readouterr().err
    assert rc_abb == 2
    assert "unrecognized arguments" in err_abb
    assert live_tok not in err_abb and live_tok.split(".")[1] not in err_abb
    assert "<redacted>" in err_abb

    # Non-JWS secret in $DATAGRANT_OIDC_TOKEN is also scrubbed by _SafeArgumentParser.error
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, "super-secret-env-token-xyz")
    rc_env_err = main(
        [
            "request",
            "--dataset",
            "d",
            "--table",
            "s.t",
            "--columns",
            "id",
            "--duration",
            "1h",
            "--purpose",
            "p",
            "--bogus=super-secret-env-token-xyz",
        ]
    )
    err_env = capsys.readouterr().err
    assert rc_env_err == 2 and "super-secret-env-token-xyz" not in err_env and "***" in err_env

    # M1: approve strict checks on stored requester_identity
    class StubConn:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    t_now = datetime(2026, 11, 5, 18, tzinfo=UTC)
    base_req = Request("alice@example.com", "clinic", "public.p", ("id",), timedelta(hours=1), "t")
    box: dict[str, rq_mod.PendingRequest] = {}
    monkeypatch.setattr(cli_mod, "_connect", lambda a: StubConn())
    monkeypatch.setattr(g_mod, "ensure_state", lambda c: [])
    monkeypatch.setattr(
        "datagrant.pg.mask.inspect_table",
        lambda c, t: TableCatalog({"id": ColumnType("pg_catalog", "int4")}, "public"),
    )
    monkeypatch.setattr(rq_mod, "get_request", lambda c, rid: box[rid])

    def write_pol(
        *, issuer: str | None = None, uclaim: str = "email", gclaim: str = "groups"
    ) -> Path:
        iss_val = issuer or idp.issuer
        pf = tmp_path / f"pol-{uclaim}-{gclaim}-{abs(hash(iss_val)) % 9999}.yaml"
        pf.write_text(
            f"version: 1\napproval: two-person\napprovers: [sec]\nmax_duration: 4h\n"
            f"groups: {{ml: [], sec: []}}\n"
            f"identity:\n  mode: oidc\n  issuer: {iss_val}\n  audience: datagrant-cli\n"
            f"  username_claim: {uclaim}\n  groups_claim: {gclaim}\n"
            f"  group_map: {{idp-ml: ml, idp-sec: sec}}\n"
            f"datasets:\n  - name: clinic\n    database: clinicdb\n    tables:\n"
            f"      - name: public.p\n        allowed_groups: [ml]\n"
            f"        columns: {{id: passthrough}}\n"
        )
        return pf

    pol_main = write_pol()
    carol_tok = keys.sign(
        _base_claims(
            idp.issuer,
            sub="sub-carol",
            email="carol@example.com",
            groups=["idp-sec"],
            roles=["idp-sec"],
            iat=now_ts - 5,
            exp=now_ts + 300,
        ),
        alg="EdDSA",
    )
    monkeypatch.setenv(oidc.OIDC_TOKEN_ENV, carol_tok)

    valid_meta: dict[str, Any] = {
        "mode": "oidc",
        "source": "oidc",
        "iss": idp.issuer,
        "sub": "sub-alice",
        "token_sha256": "a" * 64,
        "username_claim": "email",
        "groups_claim": "groups",
        "idp_groups": ["idp-ml"],
    }

    # Bad source / bad token_sha256 / mismatched issuer / mismatched username_claim -> all EXIT_FAILED (1)
    for tag, bad_patch in [
        ("bad_source", {"source": "flag"}),
        ("upper_sha", {"token_sha256": "A" * 64}),
        ("short_sha", {"token_sha256": "abc"}),
        ("missing_sha", {"token_sha256": None}),
        ("wrong_iss", {"iss": "https://other-idp.example.com"}),
        ("wrong_uclaim", {"username_claim": "sub"}),
        ("missing_uclaim", {"username_claim": None}),
    ]:
        meta = {**valid_meta, **bad_patch}
        box[tag] = rq_mod.PendingRequest(
            tag,
            base_req,
            "sha",
            "SCRAM-SHA-256$x",
            t_now,
            t_now + timedelta(hours=1),
            "pending",
            None,
            None,
            meta,
        )
        out: list[str] = []
        rc = main(["--json", "approve", "--policy", str(pol_main), tag], out.append)
        assert rc == 1, f"{tag} should fail with exit 1, got {rc}: {out}"

    # Changed groups_claim in current policy -> stored idp_groups from old claim are NOT trusted!
    pol_roles = write_pol(gclaim="roles")
    box["gclaim_changed"] = rq_mod.PendingRequest(
        "gclaim_changed",
        base_req,
        "sha",
        "SCRAM-SHA-256$x",
        t_now,
        t_now + timedelta(hours=1),
        "pending",
        None,
        None,
        dict(valid_meta),  # stored groups_claim == 'groups', policy now 'roles'
    )
    out_g: list[str] = []
    rc_g = main(["--json", "approve", "--policy", str(pol_roles), "gclaim_changed"], out_g.append)
    assert rc_g == 1 and "no longer allowed" in json.dumps(json.loads(out_g[-1])["reasons"])

    # Matching metadata succeeds dry-run approve
    box["ok_req"] = rq_mod.PendingRequest(
        "ok_req",
        base_req,
        "sha",
        "SCRAM-SHA-256$x",
        t_now,
        t_now + timedelta(hours=1),
        "pending",
        None,
        None,
        dict(valid_meta),
    )
    out_ok: list[str] = []
    assert main(["--json", "approve", "--policy", str(pol_main), "ok_req"], out_ok.append) == 0


def test_mixed_case_email_members_match_across_policy_and_oidc_tokens(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    # Policy lists mixed-case members `Alice@Corp.com` and `Carol@Corp.com` (no group_map).
    pol = parse_policy(
        {
            "version": 1,
            "approval": "two-person",
            "approvers": ["sec"],
            "max_duration": "2h",
            "groups": {"ml": ["Alice@Corp.com"], "sec": ["Carol@Corp.com"]},
            "identity": {
                "mode": "oidc",
                "issuer": idp.issuer,
                "audience": "datagrant-cli",
                "username_claim": "email",
            },
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        },
        env=INSECURE_ENV,
    )
    # Token-side lower/mixed case ("aLiCe@cOrP.com") matches policy-side "Alice@Corp.com"
    alice_tok = keys.sign(
        _base_claims(idp.issuer, sub="u-alice", email="aLiCe@cOrP.com"), alg="EdDSA"
    )
    alice_id = verify_oidc_token(
        alice_tok, pol.identity, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV
    )
    assert alice_id.username == "alice@corp.com"
    assert pol.groups_of(alice_id.username) == frozenset({"ml"})
    assert pol.groups_of("ALICE@CORP.COM") == frozenset({"ml"})
    req = Request(alice_id.username, "clinic", "public.p", ("id",), timedelta(hours=1), "debug")
    assert evaluate(pol, req).allowed

    # Approver token with mixed case ("CAROL@corp.com") matches policy-side "Carol@Corp.com"
    carol_tok = keys.sign(
        _base_claims(idp.issuer, sub="u-carol", email="CAROL@corp.com"), alg="EdDSA"
    )
    carol_id = verify_oidc_token(
        carol_tok, pol.identity, now=NOW, cache_dir=tmp_path, env=INSECURE_ENV
    )
    assert carol_id.username == "carol@corp.com"
    assert pol.can_approve(carol_id.username, alice_id.username) == []


def test_ascii_only_principal_folding_member_validation_and_local_receipt_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datagrant import cli as cli_mod
    from datagrant import receipt as receipt_mod
    from datagrant.keys import load_signing_key
    from datagrant.pg import grant as g_mod
    from datagrant.pg.mask import ColumnType, TableCatalog

    # 1. normalize_principal folds ONLY ASCII A-Z (never Unicode casefold:
    # German sharp s \u00df -> ss, Kelvin sign \u212a -> k, Latin long s \u017f -> s, ligature \ufb01 -> fi)
    assert oidc.normalize_principal("wei\u00df@corp.com") == "wei\u00df@corp.com"
    assert oidc.normalize_principal("wei\u00df@corp.com") != oidc.normalize_principal(
        "weiss@corp.com"
    )
    assert oidc.normalize_principal("\u212aelvin@corp.com") == "\u212aelvin@corp.com"
    assert oidc.normalize_principal("\u212aelvin@corp.com") != oidc.normalize_principal(
        "kelvin@corp.com"
    )
    assert oidc.normalize_principal("\u017fean@corp.com") == "\u017fean@corp.com"
    assert oidc.normalize_principal("\u017fean@corp.com") != oidc.normalize_principal(
        "sean@corp.com"
    )
    assert oidc.normalize_principal("\ufb01nance@corp.com") != oidc.normalize_principal(
        "finance@corp.com"
    )
    assert oidc.normalize_principal("Alice.B@Corp.COM") == "alice.b@corp.com"
    # Non-email local username preserves ASCII case unless email_claim=True
    assert oidc.normalize_principal("AliceAdmin") == "AliceAdmin"
    assert oidc.normalize_principal("AliceAdmin", email_claim=True) == "aliceadmin"

    # Wider Unicode casefold is kept ONLY as a defense-in-depth self-approval deny in can_approve
    pol_same_across = parse_policy(
        {
            "version": 1,
            "approval": "two-person",
            "approvers": ["sec"],
            "max_duration": "1h",
            "groups": {
                "ml": ["Alice@Corp.com", "weiss"],
                "sec": ["Alice@Corp.com", "carol@corp.com"],
            },
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        }
    )
    # Exact same spelling "Alice@Corp.com" across multiple groups is allowed and normalized
    assert pol_same_across.groups_of("alice@corp.com") == frozenset({"ml", "sec"})
    assert any(
        "different person" in r
        for r in pol_same_across.can_approve("wei\u00df", "weiss", extra_groups=frozenset({"sec"}))
    )

    # 2. Non-ASCII / whitespace / oversized group members rejected at policy load
    for bad_member in (
        "wei\u00df@corp.com",
        "\u212aelvin@corp.com",
        "\u017fean@corp.com",
        "alice smith",
        "alice\t",
        "a" * 257,
    ):
        with pytest.raises(PolicyError, match="invalid member name"):
            parse_policy(
                {
                    "version": 1,
                    "max_duration": "1h",
                    "groups": {"ml": [bad_member]},
                    "datasets": [
                        {
                            "name": "clinic",
                            "database": "clinicdb",
                            "tables": [
                                {
                                    "name": "public.p",
                                    "allowed_groups": ["ml"],
                                    "columns": {"id": "passthrough"},
                                }
                            ],
                        }
                    ],
                }
            )

    # 3. Duplicate normalized member within a group AND conflicting spellings across groups rejected
    for bad_groups, match_re in [
        ({"ml": ["alice", "alice"]}, "duplicate member"),
        ({"ml": ["Alice@Corp.com", "alice@corp.com"]}, "duplicate member"),
        ({"ml": ["Alice@Corp.com"], "sec": ["alice@corp.com"]}, "conflicting member spellings"),
    ]:
        with pytest.raises(PolicyError, match=match_re):
            parse_policy(
                {
                    "version": 1,
                    "max_duration": "1h",
                    "groups": bad_groups,
                    "datasets": [
                        {
                            "name": "clinic",
                            "database": "clinicdb",
                            "tables": [
                                {
                                    "name": "public.p",
                                    "allowed_groups": ["ml"],
                                    "columns": {"id": "passthrough"},
                                }
                            ],
                        }
                    ],
                }
            )

    # 4. Local-mode _resolve_caller normalizes email-style usernames so receipts record the authorized name
    monkeypatch.setenv("DATAGRANT_DSN", "postgresql://admin:pw@db.example:5432/clinicdb")
    monkeypatch.setenv("DATAGRANT_HASH_KEY", str(tmp_path / "k" / "hash.key"))
    monkeypatch.setenv("DATAGRANT_SIGNING_KEY", str(tmp_path / "k" / "signing.key"))
    log_path = tmp_path / "local_r.jsonl"
    monkeypatch.setenv("DATAGRANT_RECEIPT_LOG", str(log_path))
    assert main(["keys", "init", "--apply"], lambda s: None) == EXIT_OK

    class StubConn:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    def stub_apply(conn: Any, plan: g_mod.GrantPlan, sink: g_mod.ReceiptSink, **kw: Any) -> None:
        assert plan.facts is not None
        receipt_mod.append(sink.log, "issued", plan.facts, sink.key, host="h")

    monkeypatch.setattr(cli_mod, "_connect", lambda a: StubConn())
    monkeypatch.setattr(g_mod, "ensure_state", lambda c: [])
    monkeypatch.setattr(
        "datagrant.pg.mask.inspect_table",
        lambda c, t: TableCatalog({"id": ColumnType("pg_catalog", "int4")}, "public"),
    )
    monkeypatch.setattr(g_mod, "apply_plan", stub_apply)

    pol_file = tmp_path / "local.yaml"
    pol_file.write_text(
        "version: 1\napproval: auto\nmax_duration: 2h\n"
        "groups: {ml: [Alice@Corp.com]}\n"
        "datasets:\n  - name: clinic\n    database: clinicdb\n    tables:\n"
        "      - name: public.p\n        allowed_groups: [ml]\n"
        "        columns: {id: passthrough}\n"
    )
    out: list[str] = []
    rc = main(
        [
            "--json",
            "request",
            "--apply",
            "--policy",
            str(pol_file),
            "--as-user",
            "ALICE@CORP.COM",
            "--dataset",
            "clinic",
            "--table",
            "public.p",
            "--columns",
            "id",
            "--duration",
            "1h",
            "--purpose",
            "norm-check",
        ],
        out.append,
    )
    assert rc == EXIT_OK
    assert json.loads(out[-1])["requester"] == "alice@corp.com"
    rec = json.loads(log_path.read_text().splitlines()[0])["receipt"]
    assert rec["requester"] == "alice@corp.com"
    assert rec["identity"] == {"source": "flag"}
    skey = load_signing_key(tmp_path / "k" / "signing.key")
    assert receipt_mod.verify(log_path, skey.private.public_key()).ok


def test_trailing_newline_rejected_across_all_validation_regexes(
    idp: IdpState, keys: KeySet, tmp_path: Path
) -> None:
    from datagrant.pg.grant import GrantError, build_plan
    from datagrant.pg.mask import ColumnType, TableCatalog
    from datagrant.policy import Decision

    # 1. _MEMBER_RE: "alice\n" rejected at policy load
    with pytest.raises(PolicyError, match="invalid member name"):
        parse_policy(
            {
                "version": 1,
                "max_duration": "1h",
                "groups": {"ml": ["alice\n"]},
                "datasets": [
                    {
                        "name": "clinic",
                        "database": "clinicdb",
                        "tables": [
                            {
                                "name": "public.p",
                                "allowed_groups": ["ml"],
                                "columns": {"id": "passthrough"},
                            }
                        ],
                    }
                ],
            }
        )

    # 2. _IDENT_RE and _NAME_RE in policy.py: trailing newline rejected on group, dataset, db, column, claim
    for bad_doc in [
        {
            "version": 1,
            "max_duration": "1h",
            "groups": {"ml\n": ["alice"]},
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml\n"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        },
        {
            "version": 1,
            "max_duration": "1h",
            "groups": {"ml": ["alice"]},
            "datasets": [
                {
                    "name": "clinic\n",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        },
        {
            "version": 1,
            "max_duration": "1h",
            "groups": {"ml": ["alice"]},
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb\n",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        },
        {
            "version": 1,
            "max_duration": "1h",
            "groups": {"ml": ["alice"]},
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p\n",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        },
        {
            "version": 1,
            "max_duration": "1h",
            "groups": {"ml": ["alice"]},
            "identity": {
                "mode": "oidc",
                "issuer": "https://idp.example.com",
                "audience": "a",
                "username_claim": "email\n",
            },
            "datasets": [
                {
                    "name": "clinic",
                    "database": "clinicdb",
                    "tables": [
                        {
                            "name": "public.p",
                            "allowed_groups": ["ml"],
                            "columns": {"id": "passthrough"},
                        }
                    ],
                }
            ],
        },
    ]:
        with pytest.raises(PolicyError):
            parse_policy(bad_doc)

    # 3. _SUB_RE: "user-alice\n" in JWT sub rejected
    tok_bad_sub = keys.sign(_base_claims(idp.issuer, sub="user-alice\n"), alg="EdDSA")
    with pytest.raises(IdentityError, match="sub"):
        verify_oidc_token(
            tok_bad_sub,
            _cfg(idp.issuer, username_claim="email"),
            now=NOW,
            cache_dir=tmp_path,
            env=INSECURE_ENV,
        )

    # 4. _USERNAME_RE: "alice@example.com\n" in JWT username claim rejected
    tok_bad_user = keys.sign(_base_claims(idp.issuer, email="alice@example.com\n"), alg="EdDSA")
    with pytest.raises(IdentityError, match="email"):
        verify_oidc_token(
            tok_bad_user,
            _cfg(idp.issuer, username_claim="email"),
            now=NOW,
            cache_dir=tmp_path,
            env=INSECURE_ENV,
        )

    # 5. _PRINTABLE_TOKEN_RE / _B64U_RE: trailing newline in URL and base64url segment rejected
    with pytest.raises(ValueError):
        oidc.validate_oidc_url("https://idp.example.com\n", "issuer")
    with pytest.raises(IdentityError):
        oidc._b64u_decode("YQ\n", "seg")

    # 6. _GRANT_ID_RE: trailing newline in grant_id rejected
    dec = Decision(True, ("ok",), "auto", "a" * 64, {"id": "passthrough"}, 1, "clinic")
    r = Request("alice", "clinic", "public.p", ("id",), timedelta(hours=1), "t")
    cat = TableCatalog({"id": ColumnType("pg_catalog", "int4")}, "public")
    with pytest.raises(GrantError, match="grant id"):
        build_plan(dec, r, database="db", password="pw", catalog=cat, grant_id="abcdef012345\n")
