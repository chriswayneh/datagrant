# Design: BigQuery (v0.7.0+ / M5)

Status: M5 Inception. Design pending approval. No runtime. Do not start construction until Chris records an approval in [audit.md](../../aidlc-docs/audit.md).

M4 (v0.6.0) shipped Snowflake. ROADMAP next item is **the same request, mask, expire, revoke, sweep and receipt model on BigQuery** (IAM / authorized views, not a password user). Target **v0.7.0+**. Rate limits, `max_rows`, and break-glass stay out.

Grounded in the v0.6.0 code on `main` (`src/datagrant/cli.py`, `policy.py`, `pg/grant.py`, `sf/grant.py`, `receipt.py`, `docs/design/warehouses.md`, `docs/security.md`, `docs/policy.md`).

## Goal

v0.6.0 can issue, approve, receipt, revoke and sweep **Postgres and Snowflake** grants. Teams that store PHI/PII in BigQuery still cannot use datagrant there. BigQuery has no LOGIN role and no per-grant password. Access is IAM. A warehouse admin can already read the data; datagrant's job is a short, masked, receipted path for a named requester.

M5 adds **`engine: bigquery`** so a developer can ask for columns and rows, get short masked access, and leave a signed receipt, without turning datagrant into a hosted service or a second product.

Out of scope for M5: a third warehouse, rate limits, `max_rows`, `max_bytes_billed` as a policy key, break-glass, a hosted service, ticketing, SSO beyond the existing OIDC CLI boundary, PyPI publish, per-grant service-account JSON keys, BigQuery policy tags / data masking as the grant, row access policies on the source table, live BigQuery in GitHub Actions, and replacing `make demo`. Emergency access stays a reviewed policy edit to `approval: auto`.

## What is already true (do not rebuild)

| Behavior | Where | Keep as-is |
| --- | --- | --- |
| Deny-by-default YAML; unknown keys are errors; `policy.version` is `1` | `policy.py` | New keys optional. Omit `engine` or `engine: postgres` is today's Postgres. `engine: snowflake` is unchanged. |
| CLI dry run unless `--apply`; exit codes 0-4 | `cli.py` | Same commands. BigQuery `--apply` uses ADC, not a password DSN. |
| Local or OIDC identity on `request` / `approve` | `cli.py`, `oidc.py` | CLI identity stays a CLI boundary. BigQuery also needs a **Google principal** to bind IAM to (Decision 1). |
| Receipts version 1, local JSONL, optional sink | `receipt.py` | No new events required. Engine name and Google principal may be additive on `issued` facts. Never access tokens. |
| Hash key and signing key files (0600, no symlinks) | `keys.py` | Same local files. The hash key is **not** copied into BigQuery view SQL (see [Hash key](#hash-key)). |
| Postgres and Snowflake grant/revoke/sweep | `pg/`, `sf/` | Unchanged. M5 does not rewrite them. |
| `make demo` is local Postgres two-person | `scripts/demo.py` | Stay that way. |
| Per-dataset `engine`; mixed files parse | M4 | Add `bigquery` as a third value. Unknown engines stay errors. |
| No break-glass, no rate limits, no `max_rows` | Chris | Still out. |

## Scope judgment

| Candidate | Verdict | Why |
| --- | --- | --- |
| BigQuery grant path (authorized view, IAM bind to a Google principal, IAM condition expiry, sweep) | **Keep** (recommended) | Matches ROADMAP: IAM / authorized views, not a password user. Decision 1, 8. |
| Per-grant service account plus a JSON key shown once | **Cut** | Long-lived secret. Org policies often forbid key creation. SA quota is typically 100 per project. Decision 1. |
| Per-grant service account, impersonation only, no keys | **Cut** for M5 | Still burns SA quota and extra IAM. Revisit later if a team has no Google user/group for the requester. |
| Core CLI path: `request`, `approve`, `revoke`, `sweep`, `grant list/status`, receipts, `policy check` | **Keep** | That is the product. Decision 2. |
| Port doctor, advisory lock, PUBLIC preflight, `SET log_statement` to BigQuery | **Cut** | Those close Postgres host gaps. Concurrent sweep vs issue is a `datagrant.grants` row plus a 10-minute grace, same idea as Snowflake. |
| Masked **authorized views** (same five mask names) | **Keep** (recommended) | One receipt and one revoke path. Decision 3. |
| Policy tags / BigQuery column data masking as the grant | **Cut** | Project-wide, not per-grant, not time-boxed, different revoke. Decision 3. |
| Row filter as view `WHERE` | **Keep** (recommended) | Same as Postgres/Snowflake. Decision 4. |
| Row access policies on the source table | **Cut** | A RAP on the base table affects every reader, not one grant. Decision 4. |
| Operator auth: ADC / workload identity / optional impersonation | **Keep** (recommended) | No long-lived secret in a DSN. Decision 5. |
| Operator JSON key as `--bigquery-dsn` / `credentials_path` | **Cut** | Same class of secret Snowflake refused for passwords. Decision 5. |
| Hash key inlined in view SQL | **Cut** | Lands in view DDL and job history. |
| Hash key in a restricted table plus an authorized SQL UDF | **Keep** (recommended) | View text calls the UDF; the grantee never `SELECT`s the table. See [Hash key](#hash-key). |
| Optional extra `datagrant[bigquery]` | **Keep** | Postgres/Snowflake installs do not pull a GCP client. |
| Live BigQuery in GitHub Actions | **Cut** | Needs a project and billing. Decision 6. |
| Recorded RPC unit tests; live tests behind `DATAGRANT_TEST_BIGQUERY` | **Keep** (recommended) | CI stays green. Decision 6. |
| Change `make demo` to BigQuery | **Cut** | The GIF and CI demo stay Postgres. Decision 7. |
| IAM condition as the only expiry, no sweep | **Cut** | Conditions do not drop views or cancel jobs. Decision 8. |
| Sweep drops views; IAM condition is a backstop | **Keep** (recommended) | Same 1-minute cadence as Snowflake. Decision 8. |
| Revoke: drop the view first, then IAM, jobs.cancel best-effort | **Keep** (recommended) | IAM can lag; a missing view fails closed. Decision 9. |
| Policy keys for `max_bytes_billed` / custom quotas | **Cut** | Same family as `max_rows`. Decision 10. |
| Dedicated grant project plus existing GCP budgets | **Keep** (recommended) | Cost control stays with the cloud bill, not a new YAML key. Decision 10. |
| `policy.version` bump | **Cut** | Omit new keys = v0.6.0. |

## Operator configuration

`policy.version` stays `1`. Unknown keys remain errors. New keys are optional.

```yaml
version: 1
approval: two-person
approvers: [sec]
max_duration: 8h
groups:
  ml: [alice]
  sec: [carol]
datasets:
  - name: clinic
    database: clinicdb          # Postgres (omit engine)
    tables:
      - name: public.patients
        allowed_groups: [ml]
        columns: {patient_id: passthrough, ssn: hash}
  - name: bq_clinic
    engine: bigquery
    database: clinic-proj       # GCP project id
    schema: clinic_ds           # BigQuery dataset id
    location: US                # optional; must match the source dataset
    tables:
      - name: clinic_ds.patients
        allowed_groups: [ml]
        columns:
          patient_id: passthrough
          ssn: hash
        filter_columns: [region]
        row_filters:
          - "region = 'west'"
```

Validation (`datagrant policy check` enforces this offline):

- `engine`: `postgres` (default, including omitted), `snowflake`, or `bigquery`. Unknown strings are errors. A table-level `engine` is an unknown-key error.
- For `engine: bigquery`, `database` is the GCP project id and `schema` is the dataset id. Table `name` stays `dataset.table` (or `project.dataset.table` only if it matches `database`). `schema` is valid for `snowflake` and `bigquery` only.
- Optional dataset `location` is only valid on `engine: bigquery`. Omit it and `--apply` reads the source dataset location. The grant view dataset must be in that location (BigQuery authorized views do not cross regions).
- Omitting `engine` on every dataset is v0.5.0. `engine: snowflake` without `bigquery` is v0.6.0.
- Operator login is **ADC** (Application Default Credentials), optional impersonation of a dedicated operator SA, and a secret-free locator (`--bigquery-project` / `$DATAGRANT_BIGQUERY_PROJECT`, optional location). A JSON key path, `credentials_path`, or `private_key` in a locator is refused (exit 2), same class as a Snowflake password DSN. Prefer env vars over flags (`ps` / shell history). Postgres and Snowflake `--apply` do not read BigQuery settings.
- `hash`, `redact`, `partial`, `null`, `passthrough` keep the same names. BigQuery `hash` is HMAC-SHA256 via the authorized UDF. Hashes are **not designed to be joinable** with Postgres or Snowflake hashes of the same value (different HMAC output encoding). Use separate `hash_scope` values.

No other policy keys in M5. Rate limits, `max_rows`, and `max_bytes_billed` are not added.

## Login (there is no password user)

BigQuery does not issue a LOGIN role. The grantee is a **Google principal** already: `user:alice@example.com`, `group:ml@example.com`, `serviceAccount:sa@proj.iam.gserviceaccount.com`, or a workforce/workload `principal://...` string.

M5 binds that principal to a **per-grant authorized view** with an **IAM condition** `request.time < expires_at` (Decision 1, 8):

1. Resolve the Google principal (see below). Refuse `--apply` if it is missing (exit 2).
2. Create the authorized view in a datagrant-owned dataset in the same location as the source (masks call the hash UDF; see [Hash key](#hash-key)). Nobody but the operator can query it yet.
3. Authorize that view on the source dataset.
4. Write the `issued` receipt. If the receipt cannot be written: drop the view and the source authorization. No `issued` receipt, no access.
5. Bind the principal on the **view dataset** with a custom grantee role (query data, not table metadata) plus `roles/bigquery.jobUser` on a dedicated grant project, with the expiry condition. That bind is the ENABLE step.
6. Flip `datagrant.grants` to `active` only after the bind succeeds.

**Where the principal comes from.** OIDC: a configured claim (default `email`) turned into `user:<email>` unless the claim is already an IAM member string. Local mode: `--google-principal` (full IAM member string). A local `request` / `approve` without `--google-principal` is exit 2. `--as-user` still records the CLI name on the receipt; it is not a Google identity.

**Two-person.** `request --apply` stores the principal plus the pending row. It creates no view and no IAM bind. The final `approve --apply` runs the fail-safe sequence. Pending rows past `pending_ttl` expire in place; there is nothing in BigQuery to drop.

**Not in M5:** minting a per-grant service account key, showing a JSON key, or asking the developer to `gcloud auth` as a throwaway SA.

Decision 1.

## CLI and grant model (BigQuery)

**Connect.** `request` / `approve` / `revoke` / `sweep` / `grant list` for a BigQuery dataset use ADC (optional impersonation). Dry runs print the SQL and IAM plan and do not call GCP unless catalog inspect already needs a live project (recommended: dry run does not connect; `--apply` inspects `INFORMATION_SCHEMA.COLUMNS`). `--apply` without ADC or without `$DATAGRANT_BIGQUERY_PROJECT` / `--bigquery-project` is exit 2. Missing extra `datagrant[bigquery]` is exit 2 and names the extra. Run `datagrant sweep --apply` every 1 minute.

**When this sequence runs.** `approval: auto` `--apply`, and the final two-person `approve --apply`. Not at two-person `request`.

**BigQuery DDL is not one warehouse transaction.** Grant state is **one store**: table `datagrant.grants` in the operator project (dataset `datagrant`). Fail-safe order (each step its own RPC):

1. Insert into `datagrant.grants` with `status = 'issuing'` and `started_at` (now). Any host's sweep can see the in-flight grant.
2. Create the **authorized view** in `datagrant_views` (same location as the source). Alias the source as `` `SRC` `` and qualify filter and source columns as `` `SRC`.`COL` `` so an `IS NULL` filter on a `null`-masked column uses the base column (same as Snowflake).
3. Add the view as an authorized view (or authorized dataset, if construction finds that cleaner for a single view dataset) on the **source** dataset. The view owner can read source data; the grantee still cannot.
4. Update that same `datagrant.grants` row (view id, principal, fingerprint of the IAM member string) only while `STATUS = 'issuing'` (rowcount 1). If 0 rows, reverse-drop and raise.
5. Write the `issued` receipt. On failure: reverse-drop (view, source authorization). Set the row to `failed`. No `issued` receipt, no IAM bind.
6. Claim `issuing` to `enabling` (rowcount 1). If 0 rows, reverse-drop and raise. Do not bind IAM.
7. **Bind IAM last:** principal + expiry condition on the view dataset, and `jobUser` on the grant project with the same condition.
8. Flip the row to `active` only from `enabling` (rowcount 1). If the bind fails, or the active claim is 0 rows: remove the bind if it was created, drop the view and source authorization, set the row to `failed`, write a `revoked` / `failed` receipt so a revoked grant cannot return to `active`.

On **any failure** after step 2: drop what was created, **in reverse order**. Do not leave an IAM bind without a receipt. Do not leave `status = 'active'` unless the bind succeeded and the row was still `enabling`.

**Grantee role.** Do not grant `roles/bigquery.dataViewer` on the view dataset. That role includes `bigquery.tables.get`, which can read view SQL (masks and filters). Default is a custom role with `bigquery.tables.getData` (and list, if required to find the view) plus `bigquery.jobs.create` on the **grant project only**. Residual: a project owner can still read definitions; the DSN/ADC holder is trusted.

**Sweep garbage.** Sweep reads `datagrant.grants` in BigQuery. It skips `issuing` / `enabling` rows younger than **10 minutes**. After that grace, drop leftover views and IAM binds, set `failed`, write a failure receipt. Pending TTL expiry marks the request expired and does not call BigQuery DDL.

**Revoke / sweep of a live grant (Decision 9).** Fail closed:

1. **Drop the view first.** A lingering IAM bind then fails on a missing table.
2. Remove the source authorized-view entry.
3. Remove the IAM bind (view dataset and grant-project `jobUser`).
4. `jobs.cancel` for running jobs by that principal in the grant project, **best-effort**. A cancel error does not reopen access. Do not fail the revoke on cancel.
5. Mark the row revoked or expired and write the receipt.

If the view drop fails and the view still exists, exit 4 (`revoke_failed`) even if IAM remove succeeded. Access removal must not fail open on a missing receipt (exit 3 after the view is gone, same as Postgres/Snowflake).

**Expiry.** IAM condition `request.time < expires_at` is a **backstop** (new API calls deny after that instant). It does not drop the view, does not cancel jobs, and does not write a receipt. **Sub-condition expiry is not enough.** Run `datagrant sweep --apply` every 1 minute (`* * * * *`). Worst case if sweep is missed: the view remains until the next successful sweep; the IAM condition should already deny new queries after `expires_at`. If IAM propagation lags, the missing view after sweep is the close. In-flight jobs started before expiry can finish; cancel is best-effort.

**Catalog.** Column types come from `INFORMATION_SCHEMA.COLUMNS` at `--apply` (parameterized project/dataset/table). Dry run may skip inspect and emit untyped `NULL` the way Snowflake dry-run does.

**Masks (BigQuery SQL, same names):**

| Mask | Grantee sees |
| --- | --- |
| `passthrough` | The real value. |
| `redact` | The constant `[REDACTED]`. |
| `null` | NULL, cast to the column type. |
| `partial` | Asterisks plus the last 4 characters; values shorter than 8 characters fully masked. |
| `hash` | Hex HMAC-SHA256 from the authorized UDF (key not in the view text). |

**Not in M5.** `datagrant doctor` BigQuery checks, a BigQuery lock service, policy tags, RAP on source tables, per-grant SA keys, `max_bytes_billed`, network ingress controls.

Exit codes stay 0-4.

## Hash key

The local hash key file stays as today. It must **not** appear in view SQL. BigQuery keeps view DDL and job history.

**Default:** a **restricted table** (`datagrant._hash_master`) in an operator-only dataset, filled with a **query parameter** (never a SQL literal), plus an **authorized SQL UDF** (`datagrant.hash_hmac(hash_scope, value)`) that reads the table and derives the per-scope HMAC key (same idea as Postgres and Snowflake). Grant views call the UDF. The grantee role does not get access to the UDF dataset or the master table (the authorized view/UDF runs as the owner).

Invariant: **key never in view text, never in IAM JSON, never in receipts.**

Hashes are not designed to be joinable with Postgres or Snowflake (different HMAC output encoding). Keep separate `hash_scope` values.

## Threat and ops notes

- **Admin credentials still bypass the CLI.** Anyone with `bigquery.admin` or who can create views on the source can read the data. Run datagrant on a bastion that holds ADC for an operator SA with least privilege (create views in `datagrant_views`, edit IAM on that dataset, authorize views on listed source datasets, DML on `datagrant.grants`). The operator SA must not be the grantee.
- **OIDC is still a CLI boundary** unless you map a claim to a Google principal. It does not log the developer into GCP.
- **IAM lag.** Binding create/delete can take seconds, occasionally minutes. Dropping the view is the fail-closed step. Document the lag; do not wait in a retry loop that holds `--apply` open.
- **In-flight jobs.** IAM deny and view drop do not always stop a job that already started. `jobs.cancel` is best-effort. Residual: bytes already scanned are billed.
- **View SQL.** Snowflake secure views hide definition from the grantee. BigQuery `dataViewer` does not. Use the custom grantee role without `bigquery.tables.get`. Residual: project owners and the operator see DDL.
- **Authorized view to source.** The view owner (operator) can always read source columns used in the view. Least-privilege the operator SA.
- **Principal mapping.** A wrong `--google-principal` grants a different Google identity. OIDC `email` must be the Google account that will run jobs. Local mode is not authentication.
- **Hashes are not designed to be joinable** with Postgres or Snowflake.
- **No BigQuery in CI.** A missing `DATAGRANT_TEST_BIGQUERY` skips live tests. Recorded RPC still runs.
- **`make demo` stays Postgres.** Operators try BigQuery against a throwaway project they already have, after `policy check`.
- **ADC holders and GCP project owners are trusted.** Same as today's DSN holders.

## Cost and quotas

BigQuery bills **bytes scanned** by the job project (on-demand) or **slot-seconds** (editions). Creating and dropping views is metadata and is cheap. Each grantee `SELECT` bills the grant project.

M5 does **not** add `max_bytes_billed`, slot reservations, or custom quotas as policy keys (Decision 10). Operators should:

- Put grant views and `jobUser` in a **dedicated grant project** with a GCP budget and alerts.
- Not grant `jobUser` on the source project.
- Know that `INFORMATION_SCHEMA` and dry-run plans are not a substitute for a budget.

Quotas that can bite (not policy keys): IAM bindings per resource, authorized views per dataset, jobs per day. Per-grant service accounts are out, so the default 100 SAs per project is not the M5 bottleneck.

`max_concurrent_grants` stays the existing per-engine count (issuing / enabling / active in that project's `datagrant.grants`). Postgres, Snowflake, and BigQuery stores are separate; there is no cross-engine total.

## Known limits

- **IAM condition is a backstop, not sweep.** After `expires_at`, new API calls should deny, but the view remains until sweep drops it. Run `datagrant sweep --apply` every 1 minute.
- **IAM propagation.** A just-removed bind may still allow a query for a short window. A just-dropped view does not. Revoke drops the view first.
- **In-flight queries.** A job started before revoke/expiry can finish and bill. Cancel is best-effort.
- **No secure-view hide by default.** Custom role is required to keep view SQL from the grantee.
- **Same-location only.** Source dataset and grant views must share a BigQuery location.
- **`issuing` / `enabling` grace is 10 minutes.** Same crash window as Snowflake. This is not a GCP lock.
- **Local mode needs `--google-principal`.** `--as-user alice` is not an IAM member.

## Compatibility with v0.6.0

- Policies that omit `engine`, or use `postgres` / `snowflake` only, parse and evaluate as today. `policy.version` stays `1`.
- Receipt JSONL from v0.6.0 remains valid input to `receipts verify`. Additive principal fields on new BigQuery `issued` rows must not break verify of old lines.
- `make demo`, doctor, advisory lock, Snowflake DSN, and `SET LOCAL log_statement` are unchanged.
- Existing keys, Postgres DSNs, Snowflake key-pair DSNs, and runbooks keep working.
- Installing without `[bigquery]` keeps today's Postgres and Snowflake CLI. BigQuery `--apply` tells the operator to install the extra.

## Test plan (each construction PR)

- Policy: omit `engine` = postgres; `engine: bigquery` accepted; unknown engine is a parse error; table-level `engine` is an unknown-key error; `schema` / `location` refused on postgres; `policy check` covers a mixed postgres/snowflake/bigquery file; `filter_columns` required when a BigQuery `row_filters` entry names a column not in `columns`.
- Routing: a postgres or snowflake dataset never opens GCP; a bigquery dataset `--apply` without ADC / project / extra is exit 2; missing extra names `datagrant[bigquery]`; a locator with a JSON key or `credentials_path` is exit 2; dry run does not require ADC.
- Principal: OIDC email maps to `user:<email>`; local without `--google-principal` is exit 2; receipts store the IAM member string, not a token.
- Grant RPC (unit, no network): plan inserts `issuing` before `CREATE VIEW`, authorizes the view on the source, receipt, `issuing` to `enabling`, IAM bind last, then `active` from `enabling`. A stub receipt failure must not bind IAM. A stub that flips the row away from `issuing` / `enabling` reverse-drops and does not bind. View SQL aliases `` `SRC` ``, qualifies filters, calls `datagrant.hash_hmac`, and contains no key bytes. IAM JSON has `request.time < timestamp("...")` and the principal, not a private key. Custom grantee role does not include `bigquery.tables.get`. Dry run prints the plan and creates nothing.
- Two-person pending (unit): stores principal only; no view and no IAM until final approve; pending TTL expiry does not call BigQuery DDL.
- Revoke RPC (unit): drop view first, then source authorization, then IAM bind; stub view-drop failure is `revoke_failed` / exit 4; `jobs.cancel` error does not fail the revoke if the view is gone; receipt failure after drop is exit 3.
- Sweep: skip `issuing`/`enabling` younger than 10 minutes; clean older ones; expire `active` past `expires_at`; IAM condition is not treated as a substitute for sweep.
- Compat: existing Postgres and Snowflake unit tests still pass without a BigQuery extra.
- Extra pin: `google-cloud-bigquery` with a reviewed lower/upper bound (construction PR names the range after a CVE pass). CI job `pip-audit-bigquery` installs `.[bigquery]` and runs `pip-audit`. No live BigQuery calls.
- Live (optional): if `DATAGRANT_TEST_BIGQUERY` is set (project + ADC), issue, SELECT as a throwaway principal, revoke, confirm the view is gone. Fictional data only. CI default is unset (skip).
- No real IdP, no real PHI/PII. Fictional names only.

## Follow-up PRs (construction, after this design is approved)

Same shape as M4: one concern per PR, tests in each, docs last. No rate-limit PR. No `max_rows` PR. No break-glass PR. No policy-tag PR.

1. **This PR.** Design, ROADMAP pointer, audit pointer. No runtime. Wait for Chris.
2. Policy `engine: bigquery` and ADC routing. Parse `bigquery`, `schema` as dataset, optional `location`. `--apply` requires extra + ADC + project. Refuse JSON keys. Dry run without GCP.
3. BigQuery grant engine (mocked client). `issuing` row, authorized view, source authorization, receipt, IAM bind last, `active`. Two-person stores principal only. Custom grantee role. Restricted hash table plus authorized SQL UDF. Reverse-drop.
4. BigQuery revoke and sweep. Drop view first; IAM remove; `jobs.cancel` best-effort; 10-minute issuing/enabling grace; pending TTL does not drop objects; `grant list` / `status`; rowcount claims so a revoked grant cannot return to `active`.
5. Re-enable BigQuery `--apply` for grant issue and approve (`apply_plan`, `claim_pending`, `mark_request_failed`). Concurrent cap counts all BigQuery datasets (issuing/enabling/active). Sweep every 1 minute.
6. Masks and catalog. Five mask names, `INFORMATION_SCHEMA` type inspect, `` `SRC` ``-qualified filters. Hash docs: not designed to be joinable with Postgres or Snowflake.
7. Docs, runbook, CHANGELOG, package version 0.7.0 (no tag until Chris publishes). `make demo` stays Postgres.

## Decisions for Chris

The one-line why is the whole point. Recommended picks: **1B, 2B, 3B, 4B, 5B, 6B, 7B, 8B, 9B, 10B**.

1. **How does the developer get access to BigQuery?**
   - A. Per-grant service account, JSON key or token shown once (closest to Snowflake's key pair).
   - B. Per-grant authorized view plus an IAM binding on the requester's existing Google principal, with an expiry condition.
   - C. Per-grant service account with impersonation only (no keys), still a new SA per grant.
   - **Recommend B.** ROADMAP already said IAM / authorized views, not a password user. JSON keys are long-lived secrets and many orgs forbid creating them. SA quota is a real ceiling. B uses the Google identity the developer already has.

2. **How much of today's product should BigQuery copy?**
   - A. Everything, including doctor, the writer lock, and statement-logging tricks.
   - B. The path people use: ask, approve, masked access, expiry, receipt, revoke, sweep.
   - C. Masked views only, no receipts.
   - **Recommend B.** Same as Snowflake 2B. Postgres host checks do not translate.

3. **BigQuery policy tags / data masking, or datagrant views like Postgres?**
   - A. Use policy tags and column data masking as the grant.
   - B. Keep datagrant authorized views (same five mask names).
   - C. Support both in this version.
   - **Recommend B.** Policy tags are project-wide, not a time-boxed grant. One way to grant, one way to revoke, one receipt.

4. **How do row filters work?**
   - A. Row access policies on the source table.
   - B. Re-emit the filter in the authorized view `WHERE`, with quoted identifiers and `` `SRC`.`COL` ``.
   - C. Support both in this version.
   - **Recommend B.** A RAP on the base table would apply to every reader. View `WHERE` matches Postgres and Snowflake.

5. **How does the operator authenticate to GCP?**
   - A. A service-account JSON key in a DSN or `--credentials` file.
   - B. Application Default Credentials / workload identity, optional impersonation of an operator SA, secret-free project locator. JSON keys refused.
   - C. Store a user OAuth refresh token in datagrant config.
   - **Recommend B.** Same bar as Snowflake key-pair-only DSN: no long-lived secret in argv or a datagrant-owned file. ADC and workload identity are how GCP expects bastions and CI to run.

6. **How do we test this without a BigQuery bill in GitHub Actions?**
   - A. Require a real GCP project in CI.
   - B. Check recorded RPC / SQL in tests; run live tests only when someone sets `DATAGRANT_TEST_BIGQUERY`.
   - C. No BigQuery tests.
   - **Recommend B.** Same as Snowflake 5B.

7. **Does the one-command demo need BigQuery?**
   - A. Replace today's Postgres demo.
   - B. Keep the Postgres demo; BigQuery is docs and tests.
   - C. Add a second demo that needs a GCP project, and run it in CI.
   - **Recommend B.** Same as Snowflake 6B.

8. **What ends a grant that is only two hours long?**
   - A. IAM condition only. No sweep of BigQuery objects.
   - B. Sweep drops the view every 1 minute; IAM condition is a backstop for new queries after `expires_at`.
   - C. Sweep only. No IAM condition.
   - **Recommend B.** Conditions do not drop views or write receipts. Sweep is how Postgres and Snowflake end sub-day grants. The condition covers a missed sweep for *new* queries.

9. **What makes revoke fail closed given IAM lag?**
   - A. Remove the IAM bind first, then drop the view.
   - B. Drop the view first, then remove IAM, then `jobs.cancel` best-effort. Exit 4 if the view still exists.
   - C. Cancel jobs in a loop until QUERY_HISTORY is quiet, then drop.
   - **Recommend B.** A deleted view does not serve rows even if IAM has not propagated. Cancel loops are slow, billed, and still miss jobs. Same spirit as Snowflake DISABLE-then-DROP.

10. **How do we keep a grant from scanning a petabyte?**
    - A. New policy keys (`max_bytes_billed`, slot caps) in M5.
    - B. Dedicated grant project plus GCP budgets/alerts. No new YAML keys.
    - C. Per-grant bytes cap required on every BigQuery dataset.
    - **Recommend B.** `max_rows` is already out. A bytes cap is a new product surface. Billing controls already exist in GCP.

## Decisions already on record (Chris)

1. **BigQuery was not M4.** M4 was Snowflake first. This design is the parked warehouse.
2. **Rate limits stay out.**
3. **`max_rows` stays out.**
4. **No break-glass.** Emergency path is a reviewed policy edit to `approval: auto`.
5. **M4 shipped in v0.6.0** (PRs #47 to #53, tag `v0.6.0` at `6581ab8`).
