# PCI DSS support pack

Introduced in DataGrant v0.8.0. The pack supports selected PCI DSS v4.0.1 controls for temporary warehouse access on Postgres, Snowflake, and BigQuery. Assessors evaluate the controls in the context of the organization's cardholder data environment. [PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss)

| Requirement | What DataGrant provides | Operator responsibilities |
| --- | --- | --- |
| 3.4.1 — PAN display | The `pan` mask shows at most the first six and last four digits through a grant view. Tagged PAN permits only `pan`, `redact`, or `null`. | Classify PAN columns and aliases, restrict direct warehouse access, and choose redaction when fewer digits should be visible. [PCI SSC guidance](https://www.pcisecuritystandards.org/faqs/1492/) |
| 3.3 and 3.5.1 — Account data storage | Policy validation rejects projections of tagged CVV and track data and filters that reference tagged card data. | Enforce applicable retention and deletion rules for sensitive authentication data. Protect stored PAN in source tables, exports, and backups. The view mask applies at query time. [PCI SSC guidance](https://www.pcisecuritystandards.org/faqs/1146/) |
| 7 — Need-to-know access | Policy allowlists datasets, tables, columns, and groups. Grants can require approval and expire after a configured interval. | Approve business need and scope, review entitlements, and reconcile direct warehouse permissions and inherited roles. |
| 8 — Identification and authentication | OIDC maps authenticated requesters and approvers to policy identities and groups. Separate groups can be required for approval. | Enforce unique identities, applicable MFA, account lifecycle controls, and the warehouse's session and credential controls. |
| 10 — Logging and monitoring | Signed receipts record grant lifecycle events. The report exports verified events and selected grant metadata in Markdown or JSON. | Collect warehouse and identity-provider audit events, including actual queries. Protect and retain logs, synchronize clocks, monitor activity, and investigate exceptions. |

## Configure a policy

Start with the [fictional PCI policy](../../examples/policies/pci.yaml). Adapt the source tables and OIDC group mappings, classify every exposed card-data column, and review which columns are needed for the task. The example uses separate requester and reviewer groups, a 30-minute grant cap, and a 15-minute approval window. See the [policy reference](../policy.md).

    datagrant policy check examples/policies/pci.yaml

## Review access

1. Obtain the trusted signing public key and the independently recorded head hash for the receipt snapshot under review. Generate the report from that snapshot.

       datagrant receipts report --pubkey receipt.pub --receipt-log receipts.jsonl --expect-head EXPECTED_SHA256

   Add `--json` for automated reconciliation. Compare the hash against the external record to detect loss of the log's newest entries. Keep the report in a restricted evidence store because it names users and warehouse objects. See the [CLI reference](../cli.md).

2. Review each grant ID, requester, approvers, masked columns, expiry, and any recorded revocation. Compare them with the authorization decision and scope in effect at issuance.
3. Compare the receipts with current grants, warehouse permissions, and warehouse query logs. Investigate discrepancies, remove excess access, and record who performed the review and how exceptions were resolved.

Postgres PAN masking has an integration test. Snowflake and BigQuery PAN coverage checks generated SQL. Validate the mask and access lifecycle in each target warehouse with fictional data before using the policy with cardholder data.
