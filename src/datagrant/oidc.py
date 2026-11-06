"""OpenID Connect ID token verification (design: docs/design/oidc-identity.md, PR 2).

Stdlib + ``cryptography`` only: no new runtime dependencies. Supports RS256,
ES256 and EdDSA against keys fetched from the issuer's OIDC discovery + JWKS
endpoints over HTTPS (5 s connect, 10 s hard deadline, no redirects, bounded
reads) and cached on disk with mode 0600.

IdP groups grant nothing unless explicitly mapped via ``IdentityConfig.group_map``.
Plain ``http://127.0.0.1`` / ``http://localhost`` is refused unless the test-only
switch ``DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1`` is set.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import os
import re
import ssl
import stat
import sys
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

OIDC_TOKEN_ENV = "DATAGRANT_OIDC_TOKEN"  # nosec B105 - env var name
JWKS_CACHE_DIR_ENV = "DATAGRANT_JWKS_CACHE_DIR"
INSECURE_LOCALHOST_ENV = "DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST"

IDENTITY_MODES = frozenset({"local", "oidc"})
ALLOWED_ALGS = frozenset({"RS256", "ES256", "EdDSA"})
FORBIDDEN_HEADERS = frozenset({"crit", "jku", "jwk", "x5u", "x5c", "zip"})

MAX_TOKEN_BYTES = 16 * 1024
MAX_HTTP_BYTES = 64 * 1024
MAX_JWKS_KEYS = 64
MIN_RSA_BITS = 2048
CONNECT_TIMEOUT = 5.0
TOTAL_TIMEOUT = 10.0
REFETCH_MIN_AGE = 10.0

DEFAULT_ALGS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
DEFAULT_MAX_TOKEN_AGE = timedelta(minutes=15)
DEFAULT_CLOCK_SKEW = timedelta(seconds=60)
DEFAULT_JWKS_CACHE_TTL = timedelta(minutes=5)

_B64U_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_JWS_LIKE_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_PRINTABLE_TOKEN_RE = re.compile(r"^[\x21-\x7e]+$")
_SUB_RE = re.compile(r"^[\x20-\x7e]{1,256}$")
_USERNAME_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_LOCAL_HOSTS = ("127.0.0.1", "localhost")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


class IdentityError(RuntimeError):
    """OIDC token reading, discovery/JWKS fetch, or claim/signature check failed."""


@dataclass(frozen=True)
class IdentityConfig:
    """Validated ``policy.identity`` block."""

    mode: str = "local"
    issuer: str = ""
    audience: tuple[str, ...] = ()
    algorithms: frozenset[str] = frozenset(DEFAULT_ALGS)
    username_claim: str = "sub"
    groups_claim: str | None = None
    allowed_groups: frozenset[str] = frozenset()
    group_map: Mapping[str, str] = field(default_factory=dict)
    max_token_age: timedelta = DEFAULT_MAX_TOKEN_AGE
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW
    jwks_cache_ttl: timedelta = DEFAULT_JWKS_CACHE_TTL


@dataclass(frozen=True)
class VerifiedIdentity:
    """Result of verifying a caller's identity."""

    username: str
    source: str  # "oidc" | "os" | "flag"
    iss: str | None = None
    sub: str | None = None
    token_sha256: str | None = None
    mapped_groups: frozenset[str] = frozenset()
    idp_groups: tuple[str, ...] = ()
    username_claim: str | None = None
    groups_claim: str | None = None

    def receipt_dict(self) -> dict[str, str]:
        out: dict[str, str] = {"source": self.source}
        if self.source == "oidc":
            if self.iss is not None:
                out["iss"] = self.iss
            if self.sub is not None:
                out["sub"] = self.sub
            if self.token_sha256 is not None:
                out["token_sha256"] = self.token_sha256
        return out

    def approver_receipt_dict(self) -> dict[str, str]:
        return {"approver": self.username, **self.receipt_dict()}

    def request_state_dict(self) -> dict[str, Any]:
        mode = "oidc" if self.source == "oidc" else "local"
        out: dict[str, Any] = {"mode": mode, **self.receipt_dict()}
        if self.source == "oidc":
            if self.username_claim is not None:
                out["username_claim"] = self.username_claim
            out["groups_claim"] = self.groups_claim
            if self.idp_groups:
                out["idp_groups"] = list(self.idp_groups)
        return out


def allow_insecure_localhost(env: Mapping[str, str] | None = None) -> bool:
    e = os.environ if env is None else env
    return e.get(INSECURE_LOCALHOST_ENV) == "1"


def validate_oidc_url(
    url: str, what: str, *, allow_localhost_http: bool = False
) -> urllib.parse.SplitResult:
    """Require ``https://host...`` with no credentials/query/fragment."""
    if not isinstance(url, str) or not url or not _PRINTABLE_TOKEN_RE.match(url):
        raise ValueError(f"{what}: URL must be a non-empty ASCII string without whitespace")
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        _ = u.port
    except ValueError:
        raise ValueError(f"{what}: malformed URL") from None
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise ValueError(f"{what}: URL must not contain credentials")
    if u.query or u.fragment:
        raise ValueError(f"{what}: URL must not have a query or fragment")
    if not host:
        raise ValueError(f"{what}: URL has no host")
    if u.scheme == "https":
        return u
    if u.scheme == "http" and host in _LOCAL_HOSTS:
        if allow_localhost_http:
            return u
        raise ValueError(
            f"{what}: plain http:// localhost URL requires ${INSECURE_LOCALHOST_ENV}=1"
        )
    raise ValueError(f"{what}: URL must use https")


def normalize_principal(name: str, *, email_claim: bool = False) -> str:
    """Fold ASCII A-Z to a-z on email-style usernames (never Unicode casefold)."""
    return name.translate(_ASCII_LOWER) if (email_claim or "@" in name) else name


def token_sha256(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("ascii")).hexdigest()


def redact_token(text: str, raw_token: str | None) -> str:
    if not raw_token:
        return text
    stripped = raw_token.strip()
    out = text.replace(raw_token, "***")
    return out.replace(stripped, "***") if stripped else out


def _safe_path_label(path: Path) -> str:
    """Never echo a path that looks like an accidentally pasted compact JWS."""
    raw = str(path)
    if _JWS_LIKE_RE.search(raw):
        return "<redacted token-like path>"
    return raw


MAX_JSON_DEPTH = 32


def _check_json_depth(obj: Any, what: str) -> None:
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise IdentityError(f"{what} is nested too deeply")
        if isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, depth + 1) for v in cur)


def _strict_json_loads(raw: bytes | str, what: str) -> Any:
    """Parse JSON rejecting NaN/Infinity, duplicate object keys, and deep nesting."""

    def no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise IdentityError(f"duplicate JSON key {k!r} in {what}")
            out[k] = v
        return out

    def no_constants(val: str) -> Any:
        raise IdentityError(f"non-standard JSON constant {val!r} in {what}")

    try:
        parsed = json.loads(raw, object_pairs_hook=no_dups, parse_constant=no_constants)
    except IdentityError:
        raise
    except (ValueError, UnicodeDecodeError):
        raise IdentityError(f"{what} is not valid JSON") from None
    except RecursionError:
        raise IdentityError(f"{what} is nested too deeply") from None
    _check_json_depth(parsed, what)
    return parsed


def default_cache_dir(env: Mapping[str, str] | None = None) -> Path:
    e = os.environ if env is None else env
    override = e.get(JWKS_CACHE_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".cache" / "datagrant" / "jwks"


def read_token_file(path: str | Path) -> str:
    """Read an OIDC token from a private (0600) regular file without following symlinks."""
    p = Path(path)
    label = _safe_path_label(p)
    if str(p) == "-":
        raise IdentityError("token file '-' (stdin) is not supported; pass a 0600 file path")
    try:
        fd = os.open(p, os.O_RDONLY | _NOFOLLOW)
    except OSError as exc:
        raise IdentityError(f"cannot open OIDC token file {label}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IdentityError(f"OIDC token file {label} is not a regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            raise IdentityError(
                f"OIDC token file {label} must not be readable by group/others (chmod 600)"
            )
        buf = b""
        while len(buf) <= MAX_TOKEN_BYTES:
            chunk = os.read(fd, MAX_TOKEN_BYTES + 1 - len(buf))
            if not chunk:
                break
            buf += chunk
    except OSError as exc:
        raise IdentityError(f"cannot read OIDC token file {label}: {exc.strerror}") from None
    finally:
        os.close(fd)
    if len(buf) > MAX_TOKEN_BYTES:
        raise IdentityError(f"OIDC token file {label} exceeds {MAX_TOKEN_BYTES} bytes")
    try:
        token = buf.decode("ascii").strip()
    except UnicodeDecodeError:
        raise IdentityError(f"OIDC token file {label} is not ASCII") from None
    if not token or not _PRINTABLE_TOKEN_RE.match(token):
        raise IdentityError(f"OIDC token file {label} does not contain a compact JWT")
    return token


def _b64u_decode(segment: str, what: str) -> bytes:
    if not segment or not _B64U_RE.match(segment):
        raise IdentityError(f"invalid {what} encoding")
    rem = len(segment) % 4
    if rem == 1:
        raise IdentityError(f"invalid {what} base64url length")
    padded = segment + ("=" * ((4 - rem) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    # Reject non-canonical trailing bits (re-encoding without '=' must match input).
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise IdentityError(f"non-canonical {what} base64url encoding")
    return raw


def _b64u_uint(val: object, what: str) -> int:
    if not isinstance(val, str) or not val:
        raise IdentityError(f"JWK {what} must be a base64url string")
    raw = _b64u_decode(val, f"JWK {what}")
    if len(raw) > 1 and raw[0] == 0:
        raise IdentityError(f"JWK {what} has leading zero byte")
    return int.from_bytes(raw, "big")


def _http_get_json(
    url: str, *, allow_localhost_http: bool, timeout: float = TOTAL_TIMEOUT
) -> dict[str, Any]:
    try:
        u = validate_oidc_url(url, "OIDC endpoint", allow_localhost_http=allow_localhost_http)
    except ValueError as exc:
        raise IdentityError(str(exc)) from None
    deadline = time.monotonic() + timeout
    host = u.hostname or ""
    port = u.port
    path = u.path or "/"
    connect = min(CONNECT_TIMEOUT, timeout)
    conn: http.client.HTTPConnection
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=connect, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=connect)
    watchdog = threading.Timer(max(deadline - time.monotonic(), 0.0), conn.close)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.connect()

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("timed out")
            return left

        if conn.sock is None:
            raise OSError("not connected")
        conn.sock.settimeout(remaining())
        conn.request(
            "GET",
            path,
            headers={
                "User-Agent": "datagrant-oidc",
                "Accept": "application/json",
                "Host": u.netloc,
            },
        )
        conn.sock.settimeout(remaining())
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            raise IdentityError(
                f"OIDC endpoint {url} returned redirect HTTP {resp.status} (refused)"
            )
        if resp.status != 200:
            raise IdentityError(f"OIDC endpoint {url} returned HTTP {resp.status}")
        buf = b""
        while len(buf) <= MAX_HTTP_BYTES:
            if conn.sock is not None:
                conn.sock.settimeout(remaining())
            chunk = resp.read1(4096)
            if not chunk:
                break
            buf += chunk
            remaining()
        remaining()
    except IdentityError:
        raise
    except (OSError, http.client.HTTPException, ValueError, AttributeError) as exc:
        reason = "timed out" if time.monotonic() >= deadline else (str(exc) or type(exc).__name__)
        raise IdentityError(f"OIDC endpoint {url} unreachable: {reason}") from None
    finally:
        watchdog.cancel()
        conn.close()
    if len(buf) > MAX_HTTP_BYTES:
        raise IdentityError(f"OIDC endpoint {url} response exceeds {MAX_HTTP_BYTES} bytes")
    doc = _strict_json_loads(buf, f"OIDC endpoint {url} response")
    if not isinstance(doc, dict):
        raise IdentityError(f"OIDC endpoint {url} JSON top level must be an object")
    return doc


def _cache_file(cache_dir: Path, issuer: str) -> Path:
    digest = hashlib.sha256(issuer.encode("utf-8")).hexdigest()
    return cache_dir / f"{digest}.json"


def _check_cache_dir_stat(st: os.stat_result, cdir: Path) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise IdentityError(f"JWKS cache directory {cdir} must not be a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise IdentityError(f"JWKS cache path {cdir} is not a directory")
    if sys.platform != "win32":
        euid = os.geteuid()
        if st.st_uid != euid:
            raise IdentityError(f"JWKS cache directory {cdir} is not owned by current uid {euid}")
        if st.st_mode & 0o077:
            raise IdentityError(
                f"JWKS cache directory {cdir} must not be accessible by group/others (chmod 700)"
            )


def _ensure_cache_dir(cdir: Path) -> None:
    """Ensure ``cdir`` exists and is private. Only chmod directories we create ourselves."""
    missing: list[Path] = []
    cur = cdir
    while True:
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            missing.append(cur)
            parent = cur.parent
            if parent == cur:
                break
            cur = parent
        except OSError as exc:
            raise IdentityError(
                f"cannot inspect JWKS cache directory {cur}: {exc.strerror}"
            ) from None
        else:
            if cur == cdir:
                _check_cache_dir_stat(st, cdir)
            elif stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise IdentityError(f"JWKS cache parent {cur} must be a real directory")
            break
    for d in reversed(missing):
        try:
            os.mkdir(d, 0o700)
            if sys.platform != "win32":
                os.chmod(d, 0o700)
        except FileExistsError:
            try:
                st = os.lstat(d)
            except OSError as exc:
                raise IdentityError(
                    f"cannot inspect JWKS cache directory {d}: {exc.strerror}"
                ) from None
            if d == cdir:
                _check_cache_dir_stat(st, cdir)
        except OSError as exc:
            raise IdentityError(f"cannot create JWKS cache directory {d}: {exc.strerror}") from None
    try:
        _check_cache_dir_stat(os.lstat(cdir), cdir)
    except OSError as exc:
        raise IdentityError(f"cannot inspect JWKS cache directory {cdir}: {exc.strerror}") from None


def _read_cache(path: Path) -> dict[str, Any] | None:
    cdir = path.parent
    try:
        dir_st = os.lstat(cdir)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise IdentityError(f"cannot inspect JWKS cache directory {cdir}: {exc.strerror}") from None
    _check_cache_dir_stat(dir_st, cdir)
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise IdentityError(f"cannot open JWKS cache {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IdentityError(f"JWKS cache {path} is not a regular file")
        if sys.platform != "win32":
            euid = os.geteuid()
            if st.st_uid != euid:
                raise IdentityError(f"JWKS cache {path} is not owned by current uid {euid}")
            if st.st_mode & 0o077:
                raise IdentityError(f"JWKS cache {path} must not be readable by group/others")
        raw = b""
        while len(raw) <= MAX_HTTP_BYTES * 2:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            raw += chunk
    except OSError as exc:
        raise IdentityError(f"cannot read JWKS cache {path}: {exc.strerror}") from None
    finally:
        os.close(fd)
    if len(raw) > MAX_HTTP_BYTES * 2:
        return None
    try:
        doc = _strict_json_loads(raw, "JWKS cache")
    except IdentityError:
        return None
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("fetched_at"), (int, float))
        or isinstance(doc.get("fetched_at"), bool)
        or not math.isfinite(float(doc["fetched_at"]))
        or doc.get("issuer") is None
        or not isinstance(doc.get("keys"), list)
    ):
        return None
    return doc


def _write_cache(path: Path, doc: Mapping[str, Any]) -> None:
    _ensure_cache_dir(path.parent)
    try:
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=".jwks.")
    except OSError as exc:
        raise IdentityError(
            f"cannot create temporary JWKS cache file in {path.parent}: {exc.strerror}"
        ) from None
    tmp = Path(name)
    closed = False
    try:
        if sys.platform != "win32":
            os.fchmod(fd, 0o600)
        payload = json.dumps(doc, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
        if os.write(fd, payload) != len(payload):
            raise IdentityError("short write to JWKS cache")
        os.fsync(fd)
        os.close(fd)
        closed = True
        os.replace(tmp, path)
    except IdentityError:
        if not closed:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    except (OSError, ValueError) as exc:
        if not closed:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        msg = exc.strerror if isinstance(exc, OSError) else str(exc)
        raise IdentityError(f"cannot write JWKS cache {path}: {msg}") from None


def _usable_jwks_entries(raw_keys: object) -> list[dict[str, Any]]:
    if not isinstance(raw_keys, list) or len(raw_keys) > MAX_JWKS_KEYS:
        raise IdentityError("JWKS keys must be a list of at most 64 entries")
    out: list[dict[str, Any]] = []
    for k in raw_keys:
        if not isinstance(k, dict):
            raise IdentityError("JWKS entry must be an object")
        use = k.get("use")
        if use is not None and use != "sig":
            continue
        ops = k.get("key_ops")
        if ops is not None and (not isinstance(ops, list) or "verify" not in ops):
            continue
        out.append(k)
    return out


def _fetch_jwks(
    issuer: str, *, allow_localhost_http: bool, timeout: float = TOTAL_TIMEOUT
) -> tuple[str, list[dict[str, Any]]]:
    disc_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    disc = _http_get_json(disc_url, allow_localhost_http=allow_localhost_http, timeout=timeout)
    if disc.get("issuer") != issuer:
        raise IdentityError(
            f"OIDC discovery issuer mismatch: expected {issuer!r}, got {disc.get('issuer')!r}"
        )
    jwks_uri = disc.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise IdentityError("OIDC discovery document missing jwks_uri")
    try:
        validate_oidc_url(jwks_uri, "OIDC jwks_uri", allow_localhost_http=allow_localhost_http)
    except ValueError as exc:
        raise IdentityError(str(exc)) from None
    jwks = _http_get_json(jwks_uri, allow_localhost_http=allow_localhost_http, timeout=timeout)
    return jwks_uri, _usable_jwks_entries(jwks.get("keys"))


def _resolve_jwk(
    cfg: IdentityConfig,
    kid: str,
    *,
    cache_dir: Path,
    now_epoch: float,
    allow_localhost_http: bool,
    timeout: float,
) -> dict[str, Any]:
    ttl = cfg.jwks_cache_ttl.total_seconds()
    cfile = _cache_file(cache_dir, cfg.issuer)
    # Unsafe cache dir/file ownership, symlink or permissions MUST raise IdentityError (fail closed).
    cached = _read_cache(cfile) if ttl > 0 else None
    keys: list[dict[str, Any]] | None = None
    fetched_at = 0.0
    if cached is not None and cached.get("issuer") == cfg.issuer:
        age = now_epoch - float(cached["fetched_at"])
        if 0 <= age <= ttl:
            keys = _usable_jwks_entries(cached["keys"])
            fetched_at = float(cached["fetched_at"])

    def refresh() -> list[dict[str, Any]]:
        jwks_uri, fresh = _fetch_jwks(
            cfg.issuer, allow_localhost_http=allow_localhost_http, timeout=timeout
        )
        if ttl > 0:
            # Verify cache directory safety first (unsafe existing dir raises IdentityError),
            # then treat pure filesystem write failures (read-only fs, ENOSPC) as cache skip.
            _ensure_cache_dir(cfile.parent)
            try:
                _write_cache(
                    cfile,
                    {
                        "issuer": cfg.issuer,
                        "jwks_uri": jwks_uri,
                        "fetched_at": now_epoch,
                        "keys": fresh,
                    },
                )
            except IdentityError:
                pass
        return fresh

    if keys is None:
        keys = refresh()
        matches = [k for k in keys if k.get("kid") == kid]
    else:
        matches = [k for k in keys if k.get("kid") == kid]
        if not matches and (now_epoch - fetched_at) >= REFETCH_MIN_AGE:
            keys = refresh()
            matches = [k for k in keys if k.get("kid") == kid]

    if not matches:
        raise IdentityError(f"no matching JWK for kid {kid!r}")
    if len(matches) > 1:
        raise IdentityError(f"ambiguous JWKS: multiple keys share kid {kid!r}")
    return matches[0]


def _verify_jws_signature(
    alg: str, jwk: Mapping[str, Any], signing_input: bytes, signature: bytes
) -> None:
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != alg:
        raise IdentityError(f"JWK alg {jwk_alg!r} does not match token alg {alg!r}")
    kty = jwk.get("kty")
    try:
        if alg == "RS256":
            if kty != "RSA":
                raise IdentityError(f"RS256 requires RSA JWK, got kty={kty!r}")
            n = _b64u_uint(jwk.get("n"), "n")
            e = _b64u_uint(jwk.get("e"), "e")
            if e < 3 or e % 2 == 0:
                raise IdentityError("invalid RSA public exponent")
            pub_rsa = rsa.RSAPublicNumbers(e, n).public_key()
            if pub_rsa.key_size < MIN_RSA_BITS:
                raise IdentityError(f"RSA key size {pub_rsa.key_size} < {MIN_RSA_BITS} bits")
            pub_rsa.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        if alg == "ES256":
            if kty != "EC" or jwk.get("crv") != "P-256":
                raise IdentityError(
                    f"ES256 requires EC P-256 JWK, got kty={kty!r} crv={jwk.get('crv')!r}"
                )
            if len(signature) != 64:
                raise IdentityError("ES256 signature must be 64 bytes")
            x_raw = _b64u_decode(str(jwk.get("x") or ""), "JWK x")
            y_raw = _b64u_decode(str(jwk.get("y") or ""), "JWK y")
            if len(x_raw) != 32 or len(y_raw) != 32:
                raise IdentityError("P-256 coordinates must be 32 bytes")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der = utils.encode_dss_signature(r, s)
            pub_ec = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_raw, "big"), int.from_bytes(y_raw, "big"), ec.SECP256R1()
            ).public_key()
            pub_ec.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return
        if alg == "EdDSA":
            if kty != "OKP" or jwk.get("crv") != "Ed25519":
                raise IdentityError(
                    f"EdDSA requires OKP Ed25519 JWK, got kty={kty!r} crv={jwk.get('crv')!r}"
                )
            if len(signature) != 64:
                raise IdentityError("EdDSA signature must be 64 bytes")
            x_raw = _b64u_decode(str(jwk.get("x") or ""), "JWK x")
            if len(x_raw) != 32:
                raise IdentityError("Ed25519 public key must be 32 bytes")
            pub_ed = ed25519.Ed25519PublicKey.from_public_bytes(x_raw)
            pub_ed.verify(signature, signing_input)
            return
    except InvalidSignature:
        raise IdentityError("invalid JWT signature") from None
    except ValueError as exc:
        raise IdentityError(f"invalid JWK key material: {exc}") from None
    raise IdentityError(f"unsupported algorithm {alg!r}")


def _req_num_claim(claims: Mapping[str, Any], name: str) -> float:
    if name not in claims:
        raise IdentityError(f"missing required claim {name!r}")
    val = claims[name]
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise IdentityError(f"claim {name!r} must be a number")
    num = float(val)
    if not math.isfinite(num):
        raise IdentityError(f"claim {name!r} must be finite")
    return num


def _opt_num_claim(claims: Mapping[str, Any], name: str) -> float | None:
    if name not in claims:
        return None
    val = claims[name]
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise IdentityError(f"claim {name!r} must be a number")
    num = float(val)
    if not math.isfinite(num):
        raise IdentityError(f"claim {name!r} must be finite")
    return num


def verify_oidc_token(
    raw_token: str,
    cfg: IdentityConfig,
    *,
    now: float | None = None,
    cache_dir: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = TOTAL_TIMEOUT,
) -> VerifiedIdentity:
    """Verify a compact OIDC ID token against ``cfg``. Fails closed on every check."""
    if cfg.mode != "oidc":
        raise IdentityError("verify_oidc_token called with non-oidc IdentityConfig")
    if not isinstance(raw_token, str):
        raise IdentityError("OIDC token must be a string")
    token = raw_token.strip()
    if (
        not token
        or len(token.encode("utf-8")) > MAX_TOKEN_BYTES
        or not _PRINTABLE_TOKEN_RE.match(token)
    ):
        raise IdentityError("OIDC token is empty, oversized, or contains invalid characters")

    now_epoch = time.time() if now is None else float(now)
    skew = cfg.clock_skew.total_seconds()
    max_age = cfg.max_token_age.total_seconds()
    if not (math.isfinite(now_epoch) and math.isfinite(skew) and math.isfinite(max_age)):
        raise IdentityError("non-finite clock or token age parameter")
    if max_age <= 0 or skew < 0:
        raise IdentityError("invalid clock_skew or max_token_age")

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise IdentityError("OIDC token is not a 3-part compact JWS")
    hdr_b64, pay_b64, sig_b64 = parts
    header = _strict_json_loads(_b64u_decode(hdr_b64, "JWT header"), "JWT header")
    claims = _strict_json_loads(_b64u_decode(pay_b64, "JWT payload"), "JWT payload")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise IdentityError("JWT header and payload must be JSON objects")

    bad_hdr = FORBIDDEN_HEADERS & set(header)
    if bad_hdr:
        raise IdentityError(f"forbidden JWT header parameter(s): {sorted(bad_hdr)}")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGS or alg not in cfg.algorithms:
        raise IdentityError(f"disallowed JWT alg {alg!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > 256:
        raise IdentityError("JWT header missing valid kid")

    allow_local = allow_insecure_localhost(env)
    try:
        validate_oidc_url(cfg.issuer, "policy.identity.issuer", allow_localhost_http=allow_local)
    except ValueError as exc:
        raise IdentityError(str(exc)) from None

    cdir = Path(cache_dir) if cache_dir is not None else default_cache_dir(env)
    jwk = _resolve_jwk(
        cfg,
        kid,
        cache_dir=cdir,
        now_epoch=now_epoch,
        allow_localhost_http=allow_local,
        timeout=timeout,
    )
    signing_input = f"{hdr_b64}.{pay_b64}".encode("ascii")
    sig_bytes = _b64u_decode(sig_b64, "JWT signature")
    _verify_jws_signature(alg, jwk, signing_input, sig_bytes)

    # Claims validation (only after cryptographic verification succeeds).
    iss = claims.get("iss")
    if not isinstance(iss, str) or iss != cfg.issuer:
        raise IdentityError(f"JWT iss {iss!r} does not match expected issuer {cfg.issuer!r}")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not _SUB_RE.match(sub):
        raise IdentityError("JWT missing valid sub claim")

    allowed_aud = set(cfg.audience)
    aud = claims.get("aud")
    if isinstance(aud, str):
        if aud not in allowed_aud:
            raise IdentityError("JWT aud is not allowed")
        aud_list = [aud]
    elif isinstance(aud, list) and aud and all(isinstance(a, str) and a for a in aud):
        if not (set(aud) & allowed_aud):
            raise IdentityError("JWT aud does not intersect allowed audience")
        aud_list = aud
    else:
        raise IdentityError("JWT missing valid aud claim")
    # OIDC Core 3.1.3.7: if aud contains multiple entries, azp SHOULD/MUST be present;
    # whenever azp is present (single or multi-aud), it must be a string in allowed_aud.
    if len(aud_list) > 1 and "azp" not in claims:
        raise IdentityError("JWT with multiple audiences must include azp")
    if "azp" in claims:
        azp = claims["azp"]
        if not isinstance(azp, str) or azp not in allowed_aud:
            raise IdentityError("JWT azp is not in allowed audience")

    exp = _req_num_claim(claims, "exp")
    iat = _req_num_claim(claims, "iat")
    nbf = _opt_num_claim(claims, "nbf")
    if now_epoch - skew >= exp:
        raise IdentityError("JWT has expired")
    if iat > now_epoch + skew:
        raise IdentityError("JWT iat is in the future")
    if now_epoch - skew - iat > max_age:
        raise IdentityError("JWT exceeds max_token_age")
    if nbf is not None and now_epoch + skew < nbf:
        raise IdentityError("JWT nbf is in the future")

    raw_user = claims.get(cfg.username_claim)
    if not isinstance(raw_user, str) or not _USERNAME_RE.match(raw_user):
        raise IdentityError(f"JWT claim {cfg.username_claim!r} missing or invalid")
    if cfg.username_claim == "email" and claims.get("email_verified") is not True:
        raise IdentityError("JWT email_verified must be boolean true when username_claim is email")
    raw_user = normalize_principal(raw_user, email_claim=(cfg.username_claim == "email"))

    mapped: set[str] = set()
    if cfg.groups_claim is not None:
        raw_groups = claims.get(cfg.groups_claim)
        if raw_groups is None:
            token_groups: list[str] = []
        elif isinstance(raw_groups, list) and all(isinstance(g, str) and g for g in raw_groups):
            token_groups = raw_groups
        else:
            raise IdentityError(f"JWT groups claim {cfg.groups_claim!r} must be a list of strings")
        if cfg.allowed_groups and not (set(token_groups) & cfg.allowed_groups):
            raise IdentityError("caller is not in any policy.identity.allowed_groups")
        # Trust boundary: IdP groups grant nothing unless explicitly translated via group_map.
        for g in token_groups:
            target = cfg.group_map.get(g)
            if target is not None:
                mapped.add(target)

    return VerifiedIdentity(
        username=raw_user,
        source="oidc",
        iss=iss,
        sub=sub,
        token_sha256=token_sha256(token),
        mapped_groups=frozenset(mapped),
        idp_groups=tuple(token_groups) if cfg.groups_claim is not None else (),
        username_claim=cfg.username_claim,
        groups_claim=cfg.groups_claim,
    )
