# OIDC request and approve demo

Walk `request` then `approve` with **synthetic, short-lived ID tokens**. No real IdP, no real secrets, no production issuer.

This is documentation plus copy-paste fixtures. It is not a second `make demo` target (that GIF still uses local `--as-user` identity). The executable counterpart in CI is `tests/integration/test_cli_e2e.py::test_oidc_request_approve_revoke_and_receipts_e2e`. This matches OIDC identity in v0.3.0 (PRs #26 to #28).

## What this shows

- Token **acquisition** is outside datagrant: the CLI only verifies a compact ID token you already have.
- **Principal** comes from `username_claim` (here `email`). **Policy groups** come from static `policy.groups` plus `identity.group_map`. Unmapped IdP groups grant nothing, even when the name matches a policy group.
- **Distinct requester and approver:** same `(iss, sub)` is refused even if the email claim changed. A mapped `idp-sec` principal can approve.
- **Identity-mode enforcement:** `--as-user` is refused in `oidc` mode; `--oidc-token-file` is refused in `local` mode; a local pending request cannot be approved under an oidc policy (and the reverse).
- **Safe token input:** tokens live in `0600` files or `$DATAGRANT_OIDC_TOKEN`, never on `argv`. Receipts store `token_sha256`, not the JWT.

It does **not** show that OIDC stops someone who already holds `DATAGRANT_DSN`. That remains a known limit.

## Token acquisition (assumptions)

datagrant never:

- opens a browser or device-code flow
- calls the IdP token endpoint
- refreshes or exchanges a token
- accepts an access token in place of an ID token

In production the caller gets a short-lived ID token from their issuer (`iss`, `sub`, `aud`, `exp`, `iat`, plus whatever `username_claim` / `groups_claim` the policy names) and presents it. Here we mint EdDSA JWTs against a throwaway JWKS server on `127.0.0.1`. That needs `DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1`, which is **test-only**. Production issuers must be `https://`.

Tokens are minted with `iat` a few seconds ago and `exp` five minutes ahead, inside the default `max_token_age` of `15m`.

## Principal and group mapping

The fixture policy uses empty `policy.groups` lists on purpose:

```yaml
groups:
  ml: []
  sec: []
identity:
  username_claim: email
  groups_claim: groups
  group_map:
    idp-ml: ml
    idp-sec: sec
```

| Token | `sub` | `email` | IdP `groups` | Policy groups |
| --- | --- | --- | --- | --- |
| alice | `sub-alice` | `alice@example.com` | `idp-ml` | `ml` via `group_map` |
| carol | `sub-carol` | `carol@example.com` | `idp-sec` | `sec` via `group_map` |
| alice renamed | `sub-alice` (same) | `alice-alias@example.com` | `idp-sec` | still the same person |
| eve | `sub-eve` | `eve@example.com` | `sec` (unmapped) | none |

Email-style names fold ASCII `A-Z` to `a-z`. `email_verified` must be boolean `true` because `username_claim` is `email`.

## Prerequisites

Python 3.11+, datagrant installed from this tree (`pip install -e .`), cryptography (already a runtime dependency), and a scratch Postgres 16 where the role can create roles. Use fictional data only.

```bash
export DG_OIDC_DEMO="${DG_OIDC_DEMO:-$HOME/.cache/datagrant-oidc-demo}"
mkdir -p "$DG_OIDC_DEMO"
```

Point datagrant at a throwaway database (compose from `scripts/demo-compose.yml` is fine). **Warning:** the SQL below creates `public.patients` if you use that name; use a scratch database.

```bash
export DATAGRANT_DSN='postgresql://postgres:PASSWORD@127.0.0.1:55439/postgres'
export DATAGRANT_SIGNING_KEY="$DG_OIDC_DEMO/signing.key"
export DATAGRANT_HASH_KEY="$DG_OIDC_DEMO/hash.key"
export DATAGRANT_RECEIPT_LOG="$DG_OIDC_DEMO/receipts.jsonl"
export DATAGRANT_JWKS_CACHE_DIR="$DG_OIDC_DEMO/jwks"
export DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1   # test-only; never in production
```

Create the table (passthrough / redact, so this walkthrough does not need `pgcrypto`):

```sql
CREATE TABLE IF NOT EXISTS public.patients (
  id int,
  ssn text,
  region text
);
INSERT INTO public.patients (id, ssn, region)
SELECT 1, '000-00-0001', 'west'
WHERE NOT EXISTS (SELECT 1 FROM public.patients WHERE id = 1);
```

`000-00-0001` is not a real SSN.

## 1. Mint synthetic identities

Save the following as `$DG_OIDC_DEMO/idp.py` and run it in one terminal. It starts a local discovery + JWKS server, writes `0600` token files, and writes two policies. Leave it running.

```python
#!/usr/bin/env python3
"""Throwaway local IdP for docs/demo-oidc.md. Synthetic tokens only."""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

WORKDIR = Path(os.environ.get("DG_OIDC_DEMO", "/tmp/datagrant-oidc-demo"))
WORKDIR.mkdir(parents=True, exist_ok=True)
priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


jwks = {
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "ed-1",
            "use": "sig",
            "alg": "EdDSA",
            "x": b64u(pub),
        }
    ]
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:
        issuer = f"http://127.0.0.1:{self.server.server_address[1]}"
        if self.path == "/.well-known/openid-configuration":
            doc = {"issuer": issuer, "jwks_uri": f"{issuer}/jwks.json"}
        elif self.path == "/jwks.json":
            doc = jwks
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
threading.Thread(target=srv.serve_forever, daemon=True).start()
issuer = f"http://127.0.0.1:{srv.server_address[1]}"
now = int(time.time())


def mint(sub: str, email: str, groups: list[str]) -> str:
    hdr = b64u(json.dumps({"alg": "EdDSA", "kid": "ed-1", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {
        "iss": issuer,
        "sub": sub,
        "aud": "datagrant-cli",
        "iat": now - 5,
        "exp": now + 300,
        "email": email,
        "email_verified": True,
        "groups": groups,
    }
    pay = b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64u(priv.sign(f"{hdr}.{pay}".encode("ascii")))
    return f"{hdr}.{pay}.{sig}"


def write_token(name: str, token: str) -> Path:
    path = WORKDIR / name
    path.write_text(token + "\n", encoding="ascii")
    path.chmod(0o600)
    return path


write_token("alice.jwt", mint("sub-alice", "alice@example.com", ["idp-ml"]))
write_token("carol.jwt", mint("sub-carol", "carol@example.com", ["idp-sec"]))
write_token("alice-renamed.jwt", mint("sub-alice", "alice-alias@example.com", ["idp-sec"]))
write_token("eve.jwt", mint("sub-eve", "eve@example.com", ["sec"]))

(WORKDIR / "policy-oidc.yaml").write_text(
    f"""\
version: 1
approval: two-person
approvers: [sec]
max_duration: 8h
groups:
  ml: []
  sec: []
identity:
  mode: oidc
  issuer: {issuer}
  audience: datagrant-cli
  username_claim: email
  groups_claim: groups
  group_map:
    idp-ml: ml
    idp-sec: sec
datasets:
  - name: clinic
    database: postgres
    tables:
      - name: public.patients
        allowed_groups: [ml]
        columns:
          id: passthrough
          ssn: redact
          region: passthrough
        row_filters:
          - "region = 'west'"
"""
)
(WORKDIR / "policy-local.yaml").write_text(
    """\
version: 1
approval: two-person
approvers: [sec]
max_duration: 8h
groups:
  ml: [alice@example.com]
  sec: [carol@example.com]
datasets:
  - name: clinic
    database: postgres
    tables:
      - name: public.patients
        allowed_groups: [ml]
        columns:
          id: passthrough
          ssn: redact
          region: passthrough
        row_filters:
          - "region = 'west'"
"""
)
print(f"issuer={issuer}", flush=True)
print(f"workdir={WORKDIR}", flush=True)
print("IdP running on 127.0.0.1. Ctrl-C to stop.", flush=True)
try:
    while True:
        time.sleep(3600)
except KeyboardInterrupt:
    srv.shutdown()
```

```bash
python3 "$DG_OIDC_DEMO/idp.py"
# issuer=http://127.0.0.1:<port>
```

In a second terminal, reuse the same `DG_OIDC_DEMO` and `DATAGRANT_*` exports. Do not `cat` the `*.jwt` files into the shell history.

## 2. Keys, policy check, preflight

```bash
datagrant keys init --apply
datagrant policy check "$DG_OIDC_DEMO/policy-oidc.yaml"
# stderr warning: DATAGRANT_OIDC_ALLOW_INSECURE_LOCALHOST=1 is set
datagrant preflight --apply
```

`policy check` is offline. Discovery and JWKS happen later, on `request` / `approve`.

## 3. Safe input and mode conflicts

```bash
# oidc mode refuses --as-user (exit 2) before any IdP or database work
datagrant request --policy "$DG_OIDC_DEMO/policy-oidc.yaml" --as-user alice \
  --dataset clinic --table public.patients --columns id,ssn \
  --row-filter "region = 'west'" --duration 1h --purpose "oidc demo"
echo $?   # 2

# missing token in oidc mode (exit 2)
datagrant request --policy "$DG_OIDC_DEMO/policy-oidc.yaml" \
  --dataset clinic --table public.patients --columns id,ssn \
  --row-filter "region = 'west'" --duration 1h --purpose "oidc demo"
echo $?   # 2

# --oidc-token-file in local mode (exit 2); $DATAGRANT_OIDC_TOKEN would be ignored
datagrant request --policy "$DG_OIDC_DEMO/policy-local.yaml" \
  --oidc-token-file "$DG_OIDC_DEMO/alice.jwt" --as-user alice \
  --dataset clinic --table public.patients --columns id,ssn \
  --row-filter "region = 'west'" --duration 1h --purpose "oidc demo"
echo $?   # 2
```

A group-readable token file is exit 1 on POSIX (`chmod 644`), and the error names the path, not the contents.

## 4. Request as alice

Dry run still verifies the token (it also connects to read the table catalog):

```bash
datagrant --json request --policy "$DG_OIDC_DEMO/policy-oidc.yaml" \
  --oidc-token-file "$DG_OIDC_DEMO/alice.jwt" \
  --dataset clinic --table public.patients --columns id,ssn \
  --row-filter "region = 'west'" --duration 1h --purpose "oidc demo"
```

Then apply. Capture `request_id`. The JWT must not appear in the JSON.

```bash
datagrant --json request --apply --policy "$DG_OIDC_DEMO/policy-oidc.yaml" \
  --oidc-token-file "$DG_OIDC_DEMO/alice.jwt" \
  --dataset clinic --table public.patients --columns id,ssn \
  --row-filter "region = 'west'" --duration 1h --purpose "oidc demo"
# status=pending, identity_source=oidc, requester=alice@example.com
```

## 5. Self-approve is refused (same `sub`)

`alice-renamed.jwt` has a different email and `idp-sec` (an approver group) but the same `sub-alice`:

```bash
datagrant --json approve --apply --policy "$DG_OIDC_DEMO/policy-oidc.yaml" \
  --oidc-token-file "$DG_OIDC_DEMO/alice-renamed.jwt" REQUEST_ID
# exit 1, reasons include "approver must be a different person than the requester"
```

Eve's unmapped group `sec` does not make her an approver:

```bash
datagrant --json approve --apply --policy "$DG_OIDC_DEMO/policy-oidc.yaml" \
  --oidc-token-file "$DG_OIDC_DEMO/eve.jwt" REQUEST_ID
# exit 1, "not in an approver group"
```

Mode mismatch (oidc pending request, local policy) is exit 1, no name-only fallback:

```bash
datagrant --json approve --apply --policy "$DG_OIDC_DEMO/policy-local.yaml" \
  --as-user carol@example.com REQUEST_ID
# exit 1, "identity mode"
```

## 6. Carol approves

```bash
datagrant --json approve --apply --policy "$DG_OIDC_DEMO/policy-oidc.yaml" \
  --oidc-token-file "$DG_OIDC_DEMO/carol.jwt" REQUEST_ID
# status=granted
```

`$DATAGRANT_OIDC_TOKEN` is an equivalent input if you would rather not pass `--oidc-token-file`. Prefer the file so the token is not in the process environment of every child.

## 7. Receipts

```bash
datagrant receipts verify
```

Issued (and later revoked) receipts include additive fields on version 1 bodies. Shape:

```json
"identity": {
  "source": "oidc",
  "iss": "http://127.0.0.1:<port>",
  "sub": "sub-alice",
  "token_sha256": "<sha256 of alice's compact JWT>"
},
"approver_identities": [
  {
    "approver": "carol@example.com",
    "source": "oidc",
    "iss": "http://127.0.0.1:<port>",
    "sub": "sub-carol",
    "token_sha256": "<sha256 of carol's compact JWT>"
  }
]
```

Confirm the log has no compact JWT (`grep` for `eyJ` should miss). `revoke` and `sweep` take no token.

```bash
datagrant revoke --apply GRANT_ID
```

## Teardown

Stop the IdP (`Ctrl-C`). Remove `$DG_OIDC_DEMO` (keys, tokens, JWKS cache, receipts). Drop the scratch table or take the compose stack down (`make demo-down` if you used that Postgres). Do not reuse these JWTs; they expire in five minutes and were never real credentials.

## Security boundaries this demo does not prove

- Operators with `DATAGRANT_DSN` can still talk to Postgres without datagrant.
- Replay within `exp` and `max_token_age` is allowed: these are bearer tokens.
- The local `http://127.0.0.1` issuer is only valid because the test env switch is set.
- Discovery, JWKS, and token files are as described in [security.md](security.md#known-limits). This walkthrough does not add extra guarantees.
