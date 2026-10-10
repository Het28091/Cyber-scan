# Production work remaining — 10 October 2026

**Current owner direction:** deliver toward 12 October; blind implementation,
with testing performed by the owner. Owner reports all prerequisite inputs ready;
readiness is not verified acceptance. Use TWO_DAY_DELIVERY.md and OWNER_TEST_SHEET.md.
New owner-mode setup is IMPLEMENTED_UNVERIFIED. No agent provider calls or further
manual tests are planned under this restriction.

Production is **not accepted**. The application has working Linux journeys and
automated evidence; the outstanding acceptance below cannot be replaced by a
completion percentage or by green unit tests. Scope remains the owner-confirmed
SCOPE.md and FINAL_HANDOVER.md. This is the current checklist; older status
entries remain historical evidence.

## Mode-specific position

| Mode | Implemented and exercised | Still required |
| --- | --- | --- |
| Offline local, no AI/internet | Source/config/declaration checks, reports, installed-bundle network denial in CI, final Docker USER/stage correction | Representative owner source corpus, owner workflow/performance acceptance and final-commit installation evidence |
| Web-only, no AI | Pinned bounded HTTP, redirects/cookies/security headers, owned fixtures and actual unauthenticated DVWA observations | Dedicated authenticated session for protected target coverage, expected-case benchmark; no claim of built-in SQLi/XSS exploitation coverage |
| Online API AI | Model/readiness adapter, metadata-only disclosure, bounded schema-validated suggestions, rejection of interrupted responses, immutable findings | Privately prepared replacement key, reviewed pins/configuration, confirmed free-only account and actual provider inference/report/failure evidence |

The requested three modes do not include local-model AI testing. That testing
remains deferred; **the existing release policy still requires the `local_ai`
gate**. Deferral is not a PASS or a release-gate deletion. Resolve this deliberately
before choosing a final release candidate; do not bypass the validator.

## Prioritized remaining acceptance

| Priority / task | Work and next action | Responsible role | Current state |
| --- | --- | --- | --- |
| 1 / S2-04 | Exercise actual API configuration with free-only usage and synthetic finding metadata | Owner tests; developer assists when requested | OWNER REPORTS READY; NOT TESTED |
| 1 / S2-04 | Resolve deferred local-provider acceptance under current mandatory gate | Owner + developer | DEFERRED, release requirement remains |
| 2 / S3-03/04 | Prepare dedicated target session and a case-by-case expected result dataset; distinguish supported detectors from unsupported exercises | Owner + developer | NOT TESTED for authenticated DVWA |
| 2 / S3-01/04/05 | Independent security/quality review, dependencies and detection/mapping limits | Independent reviewer | NOT ACCEPTED; developer review is not independent |
| 2 / S4-01 | Approve workload sizes and latency/resource budgets on intended hardware | Owner | Measurements exist; budgets NOT APPROVED |
| 2 / S2-03, S4-03/04 | Owner uses profiles, all selected modes, cancellation, review/history, exports/retest and a restored copy | Owner with developer support | Automated journeys exist; owner UAT NOT RECORDED |
| 3 / S4-04 | Decide evidence retention, backup destination/frequency, support contact and response expectations, observation period and rollback triggers | Owner | DECISIONS PENDING; no automatic deletion enabled |
| 4 / S5-01/02 | Select unused version, freeze exact source, rerun required Linux/browser/scanner/provider checks, record all ten gates | Release lead after predecessor acceptance | NOT STARTED |
| 4 / S5-03/04/05 | Four stable Python bundles, fresh/offline installs, owner go/no-go, explicit publication authorization and gated publisher | Release lead + owner | NOT STARTED; candidate packaging is not publication |

No new raw source or credentials should be posted to issues/chat to satisfy these
inputs. Use private environment configuration and reviewed redacted evidence.
Existing owner permission covers continued development and testing; it does not
create an owner attestation, independent review, paid API budget or final release
authorization.

## Current developer work

S3-05/S4-04: Gitleaks 8.24.2 is prepared in a private user-local tool directory
on Kali and its real positive/clean and isolation controls PASS at `089cefe`.
The acceptance runner honors PATH instead of hardcoding `/usr/local/bin/gitleaks`.
The upstream archive checksum was verified before execution; no global installation
or sandbox exception was needed. Live OSV also passed.

S4-01/02/03: fresh operations, full-storage recovery, load/queue and isolated
Chromium exercises on Kali at `6a1d362` all PASS. Results and logs are under
`artifacts/checkpoints/production-oct9/` on the VM. These runs use disposable owned
fixtures and do not modify the owner's assessment store. Candidate packaging and
installation results are recorded separately in VERIFICATION.md; no stable build,
tag or publication is authorized by this checklist.

S4-03/04: local-wheel packaging is implemented. At `1d35d63`, 181 Kali tests
and full CI PASS; a real Python 3.13 candidate is rebuilt, installed and scanned
under seccomp network denial with PDF output. Missing/tampered wheels fail and
inherited pip settings cannot redirect dependency sources. See
[source-specific evidence](evidence/production-kali-oct10.json) and OPERATIONS.md.
This is candidate preparation, not final S5 acceptance. The previous Pillow
resolution failure is retained; no unsupported dependency version/hash was substituted.

## Final gate checklist

All ten records must genuinely PASS for the shipped commit and version:
`original_brief`, `non_ai`, `local_ai`, `api_ai`, `dashboard`, `target_workflows`,
`target_browser`, `detection_frameworks`, `owner_machine`, `linux_ci`.
Use RELEASE_ACCEPTANCE.md and the validator; this planning table grants no gate
status. Any required FAIL, SKIP, NOT TESTED, missing or stale record blocks release.
