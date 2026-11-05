# datagrant demo

One command walks the whole flow against a throwaway Postgres, using synthetic, obviously fake patient data.

```bash
pip install -e .
make demo          # or ./scripts/demo.sh ; needs Docker with the compose plugin
make demo-down     # only needed if a run was interrupted; the demo tears down on exit
```

## What happens
1. `scripts/demo.sh` generates a random Postgres password and starts `postgres:16` (digest-pinned) from `scripts/demo-compose.yml`, bound to `127.0.0.1:55439` only. A `trap` runs `docker compose down -v` on exit, removing the containers and the volume.
2. `scripts/demo.py` creates a temp dir for keys, receipts, an `offhost/` folder standing in for another host, and two policy files (auto and two-person). The policy has two datasets over the same table: `clinic` (filters on `region` through `filter_columns`, so `region` is never in the view) and `research` (its own `hash_scope`). Then it:
   1. seeds `dg_demo.patients` (8 rows such as `Fake Patient 001`, SSN `000-00-0001` (never issued), phone `555-01xx-…` (fictional range)) and prints the raw admin view;
   2. runs `keys init --apply`, `policy check` and `preflight --apply`;
   3. runs `request` with no flag: a dry run showing plan SQL with `PASSWORD '<redacted>'` and no password;
   4. runs `request --apply` (auto): alice connects and sees 4 west rows with name redacted, SSN HMAC-hashed, phone partial and birth date NULL, and the view has no `region` column; reading the raw table is refused;
   5. `hash_scope`: alice gets a grant on the `research` dataset; the same patient's SSN hashes to a different value there; that grant is revoked;
   6. two-person: the request goes pending; alice approving her own request is refused (exit 1); carol approves; alice logs in with the password she got at request time;
   7. `revoke --apply` while alice's session is open: the session is terminated;
   8. the second grant's expiry is fast-forwarded (a demo shortcut), then `sweep` (dry run) and `sweep --apply`;
   9. `receipts verify` passes (6 receipts: issued ×3, revoked ×2, expired), then again with `--expect-head <head>`;
   10. external receipt sink (`file://` into `offhost/`): `receipts push` (dry run, 6 pending), `receipts push --apply`, and `receipts verify --sink` passes; then the newest local receipt is deleted and `receipts verify --sink` fails with exit 1 (local log truncated or replaced).
3. On exit the temp dir (keys, receipts) and schema `dg_demo` are removed.

Expected output ends with:

```text
DEMO MARKER: masked-rows-ok
DEMO MARKER: hash-scope-ok
DEMO MARKER: two-person-ok
DEMO MARKER: revoke-ok
DEMO MARKER: sweep-ok
DEMO MARKER: receipts-ok
DEMO MARKER: sink-ok

DEMO OK
```

One-time passwords are printed as `<shown once to the requester>` in the demo log. The demo uses them internally to log in.

## Without Docker (existing Postgres)
Point the demo at any Postgres 13+ where the role can create roles and the `pgcrypto` extension (superuser is simplest). **Warning:** against an existing DSN the demo runs `DROP SCHEMA dg_demo CASCADE`, both at the start (before seeding) and at the end. It also leaves datagrant's state schemas (`datagrant`, `datagrant_views`) and the `pgcrypto` extension in place. Use a scratch database.

```bash
DATAGRANT_DEMO_DSN=postgresql://admin:PASSWORD@localhost:5432/scratch ./scripts/demo.sh
```

Windows (PowerShell):

```powershell
$env:DATAGRANT_DEMO_DSN = "postgresql://admin:PASSWORD@localhost:5432/scratch"
python scripts/demo.py
```

To use Docker on Windows, start the container yourself with `docker compose -f scripts/demo-compose.yml up -d --wait` (set `DATAGRANT_DEMO_PG_PASSWORD` first), run the line above, then `docker compose -f scripts/demo-compose.yml down -v`.

CI runs the demo on every push twice: `demo` against the CI Postgres service, and `demo-compose` through `make demo` (Docker compose), which also checks that teardown left no containers or volumes.
