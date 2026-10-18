# Phase 1 acceptance checklist - v30

Status: OPEN. This is the original v25 gate updated for the email-link architecture
and the user's reported staging results. It is not a new claim of completion.
The original checklist is preserved in PHASE1_CHECKLIST_V25_HISTORICAL.md.

## Evidence already available
- [x] Full Python Worker serves the staging sign-in page (user screenshot).
- [x] Remote database supported account creation and sign-in (user result).
- [x] Real email delivery and sign-in worked before API-key rotation (user result).
- [x] Registration disabled again (user confirmation).
- [x] Post-sign-out session check returned 401 (user screenshot; sequence reported).
- [x] 50 local CPython/SQLite tests pass in this review; provider calls mocked.
- [x] Email transport now sends explicit User-Agent and strips outer credential whitespace.
- [x] Safe provider status/category diagnostics added; raw bodies and secrets not logged.
- [x] Original frontend, legacy backend, logo/image/font bytes preserved.

## Still open before closing Phase 1
- [ ] Deploy v30 and verify /health AND /auth/email/status show 30.0.0.
- [ ] Confirm real delivery using the rotated key, then sign in/check session/sign out.
- [ ] Confirm live configuration matches the current Worker and DB; never upload the template.
- [ ] Resolve/lock Python runtime dependencies in the actual deployment environment.
- [ ] Measure actual Worker CPU usage for auth and CSV/report paths; free-tier fit unproven.
- [ ] Test expiry, reuse and wrong-browser rejection against deployed Worker/D1.
- [ ] Run workspace creation, CSV preview/import, report retrieval and relogin on staging.
- [ ] Verify cross-workspace isolation and role checks against actual Worker runtime.
- [ ] Retrieve a saved snapshot after redeploy/restart of the full Python Worker.
- [ ] Verify remote D1 atomic token consumption/rollback/concurrent confirmation behavior.
- [ ] Confirm staging database isolation and a recoverable backup before migration work.

PBKDF2 testing from v25 is obsolete: the active Cloudflare API uses email links.
Historical local D1 results are not rerun or recertified by this release.
Product access remains entitlement-gated. Do not bypass billing gates for users;
use only authorized isolated staging fixtures for report acceptance tests.
Phase 2 migration and production readiness are not completed by this patch.
