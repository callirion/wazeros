# Phase 1 checklist: v25

Status: PARTIALLY VERIFIED. Do not start Phase 2 as if this gate has passed.

## Passed
- [x] Re-run 31 CPython contract tests: all pass.
- [x] Install and pin Wrangler 4.149.0; include npm lockfile.
- [x] Correct compatibility date to 2026-10-13, supported by installed workerd.
- [x] Apply complete schema using Wrangler local D1.
- [x] Verify stored snapshots across separate Wrangler processes.
- [x] Verify org-scoped queries and membership lookup isolation in local D1.
- [x] Verify foreign keys and 50-snapshot database cap.
- [x] Verify sequential token reuse rejection in local D1.
- [x] Verify actual local D1 binding batch rollback after a foreign-key failure.
- [x] Verify concurrent token consumption: exactly one batch commits.
- [x] Preserve original frontend, legacy backend, billing code, and assets.

## Blocked / still open
- [ ] Resolve and lock Python runtime dependencies (npm lock is not a Python lock).
- [ ] Start full Python ASGI app in workerd/Pyodide.
- [ ] Verify Python-to-JavaScript binding conversion with real requests.
- [ ] Verify PBKDF2 availability, latency and CPU budget in Pyodide.
- [ ] Run login/import/report/relogin smoke through actual Python Worker.
- [ ] Repeat full API isolation tests against actual runtime.
- [ ] Prove snapshot retrieval after full Python Worker restart.
- [ ] Provision isolated remote staging D1 and deploy with authorized account access.
- [ ] Repeat acceptance flow against remote staging.

## Exact blockers observed

Python standalone downloads returned HTTP 404. Direct Wrangler startup initially
failed because v24 requested compatibility date 2026-10-17 while the installed
workerd supported dates only through 2026-10-13. The configuration is corrected.
Startup then failed resolving pyodide-capnp-bin.edgeworker.net, before the app
could serve requests. This is not evidence that app imports or hashing work.

No Cloudflare account action, remote deployment, data migration or email delivery
was performed. Do not send credentials in chat. Use authenticated staging tooling
in an environment able to fetch the Python runtime.

## Reproducible local D1 checks

From cloudflare/, after npm ci:

```sh
python tools/check_d1_local.py --wrangler ./node_modules/.bin/wrangler
npm run test:d1:binding
```

The Python script uses fresh temporary Wrangler persistence. The JavaScript test
uses local Miniflare D1 bindings for batch/concurrency only, not a rewritten API.
Both use synthetic test fixtures and never connect to remote databases.

The binding test does not prove Python FFI. Cross-process persistence is verified
by the Wrangler script, not by the binding-test harness. Full Python restart
acceptance remains open.

## Next action

Unblock Python runtime downloads in a suitable development environment, resolve
and lock Python packages, then run the existing runtime_smoke.py against the full
Worker. Only after local API acceptance should remote staging be provisioned.
