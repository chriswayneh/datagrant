# Security Policy

## Supported versions

| Version | Supported |
| --- | :---: |
| 0.1.x | ✅ |

datagrant is pre-1.0. Read the [security model and known limits](docs/security.md) before using it with real regulated data.

## Reporting a vulnerability

Please report security issues privately through GitHub's [private vulnerability reporting](https://github.com/chriswayneh/datagrant/security/advisories/new) for this repository. Don't open a public issue.

Include what you found, how to reproduce it, and the impact you expect. **Never include real PHI, PII, credentials or keys.** Use fictional data.

You can expect an acknowledgement within a week. Fixes are coordinated privately and credited in the CHANGELOG unless you prefer otherwise.

## Scope

In scope: privilege or data exposure beyond what a policy allows, a grant that outlives a revoke or expiry, SQL injection, forging or undetected tampering of receipts, and key handling.

Known limits listed in [docs/security.md](docs/security.md#known-limits) are documented trade-offs, not vulnerabilities. Reports that show they are worse than described are welcome.
