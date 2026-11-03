# Open questions (resolved 2026-11-02 by Chris Hickman)

1. **Approval in v1:** policy auto-approves; optional two-person `datagrant approve` mode via config. ✅
2. **Signing key storage:** local file (0600) by default, env var override. ✅
3. **Credential delivery:** one-time password printed once. ✅
4. **Hash masking:** pgcrypto keyed HMAC; key stored alongside signing key. ✅
5. **Receipt log:** local JSONL in v1 (default; external sinks deferred). ✅
6. **Python floor:** 3.11+; pyproject updated. ✅
7. **Docs:** technical-design.md folded into application-design.md and removed. ✅
