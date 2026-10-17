# v25 Phase 1 update

Read PHASE1_CHECKLIST.md first. Phase 1 is partially verified, not accepted.
Local D1 migration, persistence, isolation queries, constraints, batch rollback
and concurrent token consumption now pass through Cloudflare local tooling.
31 CPython contract tests pass again. Python Worker startup is blocked by DNS
resolution of the Pyodide runtime host; remote staging is not deployed.
Wrangler is pinned with an npm lockfile. Python dependencies are still unlocked.
The compatibility date is corrected to 2026-10-13 for the tested workerd binary.
Frontend and original v23 files remain unchanged.

## v24 implementation reference (historical validation statements below)

# Wazeros v24: Cloudflare M1 backend

## Release status

**M1 implementation candidate, not a completed Cloudflare acceptance milestone.**
The frontend and all original v23 files are unchanged. This is an additive backend
under `cloudflare/`, not a replacement for the full legacy API.

31 CPython contract tests pass using disk-backed SQLite behind a D1-shaped test
adapter. All 97 legacy backend tests pass. No workerd, Pyodide, remote D1,
live email, payment, or browser integration test was completed.

Python Worker setup was attempted twice with `uv sync` and `uv sync --python
3.13.7`; both toolchain downloads returned HTTP 404 in this environment. See
`validation/toolchain.log`. Do not interpret local SQLite tests as D1 tests.

## Implemented scope

- FastAPI Worker ASGI entrypoint, Wrangler config and a versioned D1 SQL migration.
- Direct async D1 prepared statements and atomic batches; no SQLAlchemy in Worker.
- Signup, verification/resend, login/logout, session expiry, password reset and
  session revocation. Verification/reset token consumption is atomic and single-use.
- Workspace creation/list/read and owner/admin write permissions.
- Product access enforced from expiring entitlements. No automatic free access.
- CSV preview, validation, save/list/read/delete, date/currency summaries, CSV export.
- Workspace-scoped snapshot lookup, import caps, body/row-size guards, origin checks,
  secure cookies outside development, persistent rate limits and audit events.
- Original CSV parsing/report calculations copied without modification from v23.

## Important boundaries

- This creates a NEW staging schema. No existing PostgreSQL data has been migrated.
- New staging passwords use salted PBKDF2-HMAC-SHA256 with 600,000 iterations.
  Legacy Argon2 hashes are deliberately rejected, not reinterpreted. Existing
  accounts cannot be copied into this Worker without a reviewed migration plan.
- `hashlib.pbkdf2_hmac` availability and CPU cost must be tested inside Pyodide
  before this design is accepted. Do not lower the work factor to make a test pass.
- The original Lemon Squeezy code is preserved under `backend/`. It is NOT mounted
  in the M1 Worker. Worker `/access` truthfully returns `checkout_available: false`.
  Staging access must be granted manually. Do not route paid customers to M1.
- PDF export explicitly returns 501. Claims, live revenue, dashboard, profile/team,
  operator/admin, billing and CRM integration endpoints are not ported here.
- The existing frontend is NOT pointed at this incomplete API. Selected route
  paths and core response shapes are retained, but full UI compatibility is unproven.
- Resend email integration requires an account/API key and verified sender. It is
  an external dependency, not a Cloudflare-native email service. No email was sent.
- Failed verification delivery leaves an unverified account; login and resend
  allow recovery. Provider retries/queues and reconciliation are later work.
- Use same-site HTTPS frontend/API origins (or a same-origin proxy). A frontend on
  an unrelated domain and an API on workers.dev will not work reliably with Lax
  cookies. Do not solve this by removing origin checks or cookie protections.
- No real customer or sensitive clinical data should be used in this staging build.

## Local contract tests

From `cloudflare/`, in an isolated Python environment:

```sh
python -m pip install -r requirements-local.txt
PYTHONPATH=. python -m pytest -q tests
```

These tests run on CPython 3.12 in this release. The Worker toolchain requires
Python >=3.13, as configured in pyproject.toml. Runtime dependencies are not yet
locked because toolchain resolution did not complete.

## Cloudflare staging setup (not performed in this release)

Use a new, isolated staging database and a Cloudflare account you control.
From `cloudflare/`:

```sh
uv sync
uv run pywrangler d1 create wazeros-m1-staging
```

Replace the zero UUID in `wrangler.jsonc` with the actual staging database UUID.
Keep production resources out of this config. Set `FRONTEND_URL` to the actual
same-site HTTPS staging frontend origin. The default staging+localhost config
intentionally returns 503 until corrected.

```sh
uv run pywrangler d1 migrations apply wazeros-m1-staging --local
uv run pywrangler dev --var APP_ENV:development
```

For local email testing, copy `.dev.vars.example` to `.dev.vars` and supply a real
sender/key. Keep registration disabled until runtime tests pass. For a deployed
staging environment, use a secret rather than committing an API key:

```sh
uv run pywrangler secret put MAIL_API_KEY
uv run pywrangler d1 migrations apply wazeros-m1-staging --remote
uv run pywrangler deploy
```

Set `MAIL_FROM` in staging configuration. Set `REGISTRATION_ENABLED` to `true`
only when the HTTPS origin, runtime hashing, email delivery and permissions have
been verified. Do not use `APP_ENV=development` on a deployed public Worker.

## Isolated runtime test account

The optional seed generator bypasses verification ONLY through operator-applied
SQL for a new staging test account. It creates seven-day manual test access;
there is no HTTP entitlement-grant or verification-bypass endpoint.

```sh
python tools/seed_staging.py --staging-only --email YOUR_TEST_EMAIL > staging-seed.sql
uv run pywrangler d1 execute wazeros-m1-staging --local --file staging-seed.sql
```

It prompts for a password and emits only its salted hash. Never commit generated
seed files. For remote staging, explicitly substitute `--remote` after checking
the target database. Never apply this seed to production.

```sh
python tools/runtime_smoke.py --base-url http://localhost:8787 --origin http://localhost:3000 --email YOUR_TEST_EMAIL
```

For HTTPS staging, use the deployed API URL and configured HTTPS frontend origin.
The smoke script checks health, hashing/login, workspace access, import, retrieval,
CSV export, logout/relogin and deletion. It has not been run in this release.

## Acceptance gates still open

1. Resolve and lock Python Worker dependencies; run workerd/Pyodide startup.
2. Verify PBKDF2 support, login latency and CPU budget in the actual runtime.
3. Apply migration to local D1, run smoke and isolation tests against real bindings.
4. Save a snapshot, stop/restart the Worker, and verify retrieval in a new session.
5. Repeat against isolated remote D1; test batch rollback and concurrent token use.
6. Test actual email delivery and recovery from provider failure.
7. Verify selected frontend flow in a browser without changing frontend design.
8. Exercise staging database export/restore before considering production use.

## Backup/rollback plan

Before future schema changes, export the staging database and record the deployed
Worker version. Use a new staging DB for destructive experiments. Restore a
backup into a separate DB and verify counts and workspace isolation before
rebinding. No backup/restore drill or production rollback was executed here.

## Official references checked for implementation

- https://developers.cloudflare.com/workers/languages/python/packages/fastapi/
- https://developers.cloudflare.com/d1/worker-api/d1-database/
- https://developers.cloudflare.com/d1/reference/migrations/
- https://developers.cloudflare.com/d1/platform/limits/

These establish the documented ASGI/binding/migration interfaces, not successful
execution of this specific application on Cloudflare.
