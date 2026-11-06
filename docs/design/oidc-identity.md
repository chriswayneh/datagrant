# Design: OIDC identity

Status: proposed. Docs only; nothing here is implemented yet. Roadmap item: [OIDC identity](../../ROADMAP.md).

## Goal

Today the requester and approver names come from `getpass.getuser()` or `--as-user`, so identity is recorded, not proven. Anyone who can run `datagrant` with the admin DSN can claim any name, and two-person approval is a workflow check rather than an authentication boundary.

v0.3.0 adds optional OIDC identity verification. When a policy sets `identity.mode: oidc`, every `request` and `approve` must present an OpenID Connect ID token signed by the configured issuer. The verified claim becomes the requester or approver name, `--as-user` is refused, and the receipt records cryptographic facts about the token without storing the token itself.

`identity.mode: local` stays the default, so existing policies and offline workflows keep working unchanged.

Out of scope: stopping someone who already holds the admin DSN from connecting to Postgres directly. To enforce OIDC as a real boundary, run `datagrant` behind a small service or runner that holds the admin DSN and accepts caller ID tokens. See [Security limits](#security-limits).

## Dependency choice

| Option | Pros | Cons | Verdict |
| --- | --- | --- | --- |
| `PyJWT[crypto]` | Widely audited, handles JWS and claim plumbing | Adds a runtime dependency; defaults must still be locked down (`algorithms`, `options`) to avoid footguns | Not chosen |
| Standard library + `cryptography` (already required) | Zero new runtime dependencies, matching `sink.py`; small surface (~180 lines for 3-part JWS split, strict base64url, JSON header/payload, RSA PKCS#1 v1.5 SHA-256, ECDSA P-256 SHA-256 with IEEE P1363 to DER conversion, Ed25519, and JWK `RSA`/`EC`/`OKP` parsing) | We own the parser and must test edge cases thoroughly | **Recommended** |

`cryptography>=44,<51` is already a dependency for ed25519 receipts, and `http.client` + `ssl` already power `WebhookSink` with hard deadlines and no redirects. Keeping zero new dependencies keeps the supply-chain surface flat and lets us refuse every algorithm, header and key type outside our exact allow-list by construction.

## Policy configuration

Identity rules belong in the policy file because they define who counts as a user and how groups are resolved, and they contain no secrets. `policy` gains an optional top-level `identity` mapping:

```yaml
identity:
  mode: oidc                        # "local" (default if omitted) or "oidc"
  issuer: https://idp.example.com   # required in oidc mode; exact iss match
  audience: datagrant-cli           # required in oidc mode; string or non-empty list of strings
  algorithms: [RS256, ES256, EdDSA] # optional; subset of {RS256, ES256, EdDSA}, default all three
  username_claim: email             # optional; default "sub" (e.g. "sub", "email", "preferred_username")
  groups_claim: groups              # optional; merge verified token groups with policy.groups
  allowed_groups: [eng, oncall]     # optional; require token's groups_claim to intersect this set
  clock_skew: 60s                   # optional; duration 0s..300s (parsed with s/m), default 60s
  jwks_cache_ttl: 1h                # optional; duration 0s..24h, default 1h (0s disables disk cache)
```

Validation rules (`datagrant policy check` enforces all of them offline):

- Unknown keys anywhere under `identity` are policy errors, matching the rest of `policy.py`.
- In `local` mode (or when `identity` is omitted), any other `identity.*` key is a policy error so half-configured OIDC blocks cannot silently fall back to local mode.
- `issuer` must be an `https://` URL with host, no credentials, no query and no fragment (`http://127.0.0.1` and `http://localhost` allowed for local test fixtures, same rule as `sink.py`). Trailing slash is preserved as written because OIDC `iss` comparison is exact string equality.
- `algorithms` may only name `RS256`, `ES256`, `EdDSA`. `none`, `HS256`/`HS384`/`HS512`, `RS*`/`PS*` other than `RS256`, and `ES384`/`ES512` are rejected at policy load.
- If `allowed_groups` is set, `groups_claim` is required.
- When `username_claim` is `"email"`, verification also requires claim `email_verified is True` (boolean `True`, not the string `"true"`), preventing unverified-email account takeover on IdPs that allow mutable emails.

Runtime cache location (host-specific, not in policy): optional `$DATAGRANT_JWKS_CACHE_DIR`, default `~/.cache/datagrant/jwks` (created `0700`, files `0600`, opened with `O_NOFOLLOW`).

## Token input

Tokens are bearer credentials and never appear in `argv` (which leaks via `ps` and shell history):

| Source | Flag / Env | Precedence |
| --- | --- | --- |
| Token file | `--oidc-token-file PATH` | 1 (beats env) |
| Environment | `$DATAGRANT_OIDC_TOKEN` | 2 |

Rules:

- There is **no `--oidc-token VALUE` flag**. Passing a token-looking value to `--oidc-token-file` fails when opening the path, and the error prints only the path, never file contents or `$DATAGRANT_OIDC_TOKEN`.
- `--oidc-token-file` is read like key files: `O_RDONLY | O_NOFOLLOW`, regular file only, `0600` on POSIX, max 16 KiB, stripped of trailing whitespace. `"-"` is not supported (avoids interactive hangs in cron/automation).
- In `oidc` mode: `--as-user` is refused (exit 2) before any network or database work; missing token input is refused (exit 2).
- In `local` mode: passing `--oidc-token-file` is refused (exit 2) so callers notice the policy is not checking tokens; `$DATAGRANT_OIDC_TOKEN` in the environment is ignored so shared shells stay harmless.
- Any occurrence of the raw token string is redacted (`***`) from every error, warning and JSON output, alongside DSN passwords and sink tokens. `receipt._FORBIDDEN_KEYS` gains `"id_token"`, `"oidc_token"`, `"token"` and `"access_token"`.

## Discovery, JWKS fetch and caching

1. **Discovery.** Fetch `<issuer trimmed of trailing />/.well-known/openid-configuration` over HTTPS. Require JSON object whose `"issuer"` equals `policy.identity.issuer` byte-for-byte (per OpenID Connect Discovery 1.0 section 4.3) and whose `"jwks_uri"` is a valid `https://` URL (same localhost test allowance, no credentials/query/fragment).
2. **JWKS fetch.** Fetch `jwks_uri`, parse `{"keys": [...]}` (max 64 KiB response, max 64 keys). Ignore keys with `"use"` present and not `"sig"`, or with `"key_ops"` present and not containing `"verify"`.
3. **Transport.** Reuse the `http.client` + `ssl.create_default_context()` pattern from `WebhookSink`: 5 s connect timeout, 10 s hard wall-clock deadline per request, TLS verification always on, **no redirects followed** (an open redirect on an issuer must never steer JWKS to an attacker host), no credentials in URLs.
4. **Cache.** Keyed by `sha256(issuer)`. Stores `{"fetched_at": <epoch>, "jwks_uri": ..., "keys": [...]}` atomically (`mkstemp` `0600` + `os.replace`, `O_NOFOLLOW` on read). Valid until `now - fetched_at > jwks_cache_ttl`.
5. **`kid` miss and rotation.** Look up header `kid` in cached keys. Require a unique match (0 matches -> refresh once if cache is older than 10 s, else fail; >1 matches with the same `kid` -> fail closed). Never fetch an arbitrary URL from token headers (`jku`, `x5u` and embedded `jwk` in the JWS header are ignored and, if present, rejected).

## Verification rules

Every step fails closed with `IdentityError`:

1. **Compact JWS shape.** ASCII printable, max 16 KiB, exactly two `"."` separators, non-empty header, payload and signature, strict unpadded base64url decode (reject non-canonical padding or alphabet).
2. **Header.** JSON object. Reject if `crit`, `jku`, `jwk`, `x5u`, `x5c` or `zip` is present. Require `alg` in `policy.identity.algorithms` (so `none` and `HS*` are impossible). Require non-empty string `kid`.
3. **Key binding (prevent algorithm confusion).** Match `kid` in JWKS, then enforce key-type / curve / JWK-`alg` agreement before touching the signature:
   - `RS256`: JWK `kty == "RSA"`, modulus >= 2048 bits, JWK `alg` (if present) == `"RS256"`.
   - `ES256`: JWK `kty == "EC"`, `crv == "P-256"`, JWK `alg` (if present) == `"ES256"`, JWS signature is 64 bytes (`r || s`, converted to ASN.1 DER for `cryptography`).
   - `EdDSA`: JWK `kty == "OKP"`, `crv == "Ed25519"`, JWK `alg` (if present) == `"EdDSA"`, JWS signature is 64 bytes.
4. **Signature.** Verify over `ascii(header_b64 + "." + payload_b64)`.
5. **Claims.** Payload must be a JSON object:
   - `iss`: string, exact match with `policy.identity.issuer`.
   - `sub`: non-empty string, max 256 chars, printable (always required per OIDC Core, even when `username_claim` is another claim).
   - `aud`: string equal to an allowed audience, or list of strings intersecting `policy.identity.audience`. If `aud` is a list with multiple entries and `azp` is present, `azp` must also be in `policy.identity.audience`.
   - `exp`: integer/float timestamp (reject booleans), required; fail if `now - skew >= exp`.
   - `iat`: integer/float timestamp, required per OIDC Core ID Token spec; fail if `iat > now + skew`.
   - `nbf`: if present, integer/float timestamp; fail if `now + skew < nbf`.
   - Identity claim (`username_claim`): non-empty string, printable, no control chars or whitespace, max 256 chars (note: unlike `_NAME_RE` on group names, `@` and `/` are allowed so emails and OIDC subjects work). If `username_claim == "email"`, require `email_verified is True`.
   - Groups (`groups_claim`, if configured): must be a list of strings (missing claim -> empty set unless `allowed_groups` is set, which then denies). Effective groups for policy evaluation are `policy.groups_of(principal) | verified_token_groups` (where entries matching `_NAME_RE` participate). If `allowed_groups` is set and `verified_token_groups & allowed_groups` is empty, deny.

## Requester and approver flows

Both `request` and `approve` resolve the caller through the exact same verifier before policy evaluation (including dry runs, so a dry run with `mode: oidc` also proves who is asking and checks group membership):

- **`request`**: verified identity becomes `req.requester` (stored in `datagrant.requests.requester` or `datagrant.grants.requester`, unchanged column type).
- **`approve`**: verified identity becomes `approver`. Two-person self-approval check compares **both** the resolved name (`approver == pending.requester`) **and**, when the pending request recorded an OIDC `(iss, sub)`, `(approver_iss, approver_sub) == (requester_iss, requester_sub)`. That stops the same person from approving their own request even if a mutable claim like `preferred_username` changed between request and approval.
- **`revoke` and `sweep`**: unchanged; they do not take `--policy` or user identity.

## State and receipt fields

`GrantFacts` and `datagrant.grants` / `datagrant.requests` gain optional JSON metadata (additive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` in `STATE_DDL`, just like U4 and U5, so existing databases upgrade in place on `preflight --apply` or grant):

- `datagrant.requests`: `requester_identity jsonb`
- `datagrant.grants`: `requester_identity jsonb`, `approver_identities jsonb`

Receipt bodies stay `RECEIPT_VERSION = 1` with two additive fields (`verify` checks signatures over canonical JSON of whatever keys were signed, so existing receipts and `receipts verify` remain 100% compatible):

```json
"identity": {
  "source": "oidc",
  "iss": "https://idp.example.com",
  "sub": "00u1abc2def3",
  "token_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
},
"approver_identities": [
  {
    "approver": "carol@example.com",
    "source": "oidc",
    "iss": "https://idp.example.com",
    "sub": "00u9xyz87654",
    "token_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
  }
]
```

In `local` mode, `identity` is `{"source": "os"}` or `{"source": "flag"}` (with `iss`, `sub` and `token_sha256` omitted) and `approver_identities` records `{"approver": "...", "source": "os"|"flag"}`. `token_sha256` is `sha256(raw_compact_jwt_ascii)` so an auditor who also logs IdP token issuance can correlate a grant to one exact token without the receipt ever holding a bearer credential (even an expired one).

## Failure modes and exit codes

No new exit codes; existing codes 0 to 4 keep their meanings ([CLI exit codes](../cli.md)):

| Situation | Behavior | Exit |
| --- | --- | :---: |
| `--as-user` used when `policy.identity.mode == "oidc"` | Refused before network/DB | 2 |
| `--oidc-token-file` used when `policy.identity.mode == "local"` | Refused before DB | 2 |
| Missing token (`--oidc-token-file` and `$DATAGRANT_OIDC_TOKEN` both unset) in `oidc` mode | Refused before network/DB | 2 |
| Invalid `identity` block in policy | `policy check` / load fails | 1 |
| Token file missing, symlink, `0644`, directory, or >16 KiB | Fail closed, path-only message | 1 |
| Malformed JWT, disallowed `alg`/`crit`/`jku`, `kid` miss after refresh, bad signature, expired/`nbf`/future `iat`, wrong `iss`/`aud`, `email_verified != True`, `allowed_groups` miss | Fail closed, no DB changes, token redacted | 1 |
| Discovery or JWKS endpoint unreachable, non-200, redirect, TLS error, timeout, or discovery `issuer` mismatch | Fail closed (cached JWKS within TTL still works offline; expired cache fails) | 1 |

## Security limits

- **Operators holding the admin DSN are still trusted.** On a developer laptop where the caller already has `DATAGRANT_DSN`, they could bypass `datagrant` or edit `policy.yaml`. OIDC becomes an enforced boundary when `datagrant` runs on a bastion, CI workflow, or thin wrapper where callers supply only their OIDC token and do not hold `DATAGRANT_DSN` or write access to `policy.yaml`.
- **Bearer token replay within `exp`.** Standard OIDC ID tokens are bearer tokens until `exp` (no PoP/DPoP). Use short-lived tokens (for example 5 to 15 minutes from workload identity or `oidc-agent`) and keep `--oidc-token-file` mode `0600`.
- **Revoked sessions at the IdP.** Verification checks the token signature and `exp`, not live IdP session state. Keep token lifetimes short.
- **Claim stability.** Mutable claims (`email`, `preferred_username`) can be reassigned at some IdPs. Prefer `sub` or verified corporate emails with non-recycled addresses; self-approval always checks `(iss, sub)` as well as the display name.

## Test plan

All tests run offline in CI with no external IdP:

- Local `ThreadingHTTPServer` fixture serving `/.well-known/openid-configuration` and `/jwks.json` (over `http://127.0.0.1:<port>` via the localhost test allowance), generating fresh RSA-2048, P-256 and Ed25519 keys per test session.
- Unit tests covering: valid `RS256` / `ES256` / `EdDSA` tokens; `alg: "none"` and `HS256` signed with the public key bytes (classic algorithm-confusion attack); RSA key presented with `ES256` header and vice versa; `jku`/`jwk`/`crit` header injection; expired `exp`, future `nbf`, future `iat`, boundary within `clock_skew`; wrong `iss` (including trailing-slash mismatch) and discovery `issuer` mismatch; wrong `aud` (string and list, plus `azp` mismatch); `kid` miss triggering a single JWKS refresh, repeated `kid` miss failing, duplicate `kid` failing, stale cache failing when server is down, fresh cache succeeding when server is down; redirect response refused; slow-trickle server hitting the 10 s deadline; `email_verified: false` and `"true"` (string) refused when `username_claim: email`; `groups_claim` + `allowed_groups`; token file symlink / `0644` / oversized refused; raw token never echoed in any error, warning, repr or JSON output.
- Postgres integration tests (`tests/integration/`): end-to-end `request` + `approve` in `oidc` mode, self-approval blocked by `(iss, sub)` even when display claim differs, `--as-user` rejected with exit 2, and `receipts verify` confirming the signed `identity` and `approver_identities` fields and absence of the raw token.

## Follow-up PRs

1. **PR 2: OIDC verifier and policy config (`src/datagrant/oidc.py`, `policy.py`).** `IdentityConfig` parsing and validation in `policy.py` (`policy check` works), JWS/JWK parsing and `RS256`/`ES256`/`EdDSA` verification with `cryptography`, discovery + JWKS fetch and `0600` cache, token file reader and redaction helper, plus the full unit test suite against the local JWKS server fixture. Not wired into CLI commands yet.
2. **PR 3: CLI wiring, DB state and receipts.** `--oidc-token-file` and `$DATAGRANT_OIDC_TOKEN` on `request` and `approve`, `--as-user` / mode conflict checks, `(iss, sub)` two-person enforcement, additive state columns, `identity` and `approver_identities` in receipts, token redaction in CLI errors, and Postgres integration tests.
3. **PR 4: Docs, demo and v0.3.0 prep.** `docs/policy.md`, `docs/cli.md`, `docs/security.md`, `docs/operations.md`, `README.md`, `CHANGELOG.md`, `ROADMAP.md`, mark this design implemented, and extend the demo if helpful.
