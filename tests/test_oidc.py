from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import threading
from collections.abc import Iterator, Mapping
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

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
    assert any(good_dir.glob("*.json"))
    orig_fstat = os.fstat

    class FakeStat:
        def __init__(self, st: os.stat_result) -> None:
            self.st_mode = st.st_mode
            self.st_uid = st.st_uid + 99

    monkeypatch.setattr(os, "fstat", lambda fd: FakeStat(orig_fstat(fd)))
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


def test_cli_request_and_approve_refuse_oidc_policy_before_dsn(
    idp: IdpState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # H1: request and approve fail closed (exit 1) immediately on non-local policy.identity,
    # before touching --dsn (no DSN set at all -> would exit 2 if it got past the gate).
    monkeypatch.setenv(INSECURE_LOCALHOST_ENV, "1")
    monkeypatch.delenv("DATAGRANT_DSN", raising=False)
    pol = tmp_path / "oidc.yaml"
    pol.write_text(
        f"version: 1\napproval: two-person\napprovers: [sec]\nmax_duration: 1h\n"
        f"groups: {{ml: [alice], sec: [carol]}}\n"
        f"identity:\n  mode: oidc\n  issuer: {idp.issuer}\n  audience: datagrant-cli\n"
        f"datasets:\n  - name: clinic\n    database: postgres\n    tables:\n"
        f"      - name: public.t\n        allowed_groups: [ml]\n        columns: {{id: passthrough}}\n"
    )
    out1: list[str] = []
    rc1 = main(
        [
            "--json",
            "request",
            "--policy",
            str(pol),
            "--as-user",
            "alice",
            "--dataset",
            "clinic",
            "--table",
            "public.t",
            "--columns",
            "id",
            "--duration",
            "30m",
            "--purpose",
            "t",
        ],
        out1.append,
    )
    assert rc1 == 1 and "identity.mode='oidc'" in json.loads(out1[-1])["error"]

    out2: list[str] = []
    rc2 = main(
        ["--json", "approve", "--policy", str(pol), "--as-user", "carol", "req123"], out2.append
    )
    assert rc2 == 1 and "identity.mode='oidc'" in json.loads(out2[-1])["error"]


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
