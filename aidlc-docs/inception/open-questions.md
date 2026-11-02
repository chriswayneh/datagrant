# Open questions (need maintainer decision)

1. **Approval in v1:** policy-only auto-approve, or add a second-person `datagrant approve <id>`?
2. **Receipt signing key storage:** local file (0600), env var, or pluggable KMS?
3. **Credential delivery:** print one-time password, or write a `.pgpass`/DSN file?
4. **Hash masking:** require pgcrypto (keyed HMAC) or do masking-free hashing in Python views? Key managed where?
5. **Receipt log:** local JSONL only, or also write receipts into a DB table / external sink?
6. **Python floor:** 3.11+ (this design) vs 3.10+ in earlier draft/pyproject — confirm 3.11.
7. **Name for docs:** `technical-design.md` vs new `application-design.md` — keep both or merge?
