# Verification record

## Handover restriction — 10 October 2026

`f3ce53c`: before the owner switched to blind implementation, twelve portable
source/release checks passed and the already-started Kali suite completed with
183 tests PASS in 13.413 s (`artifacts/checkpoints/release-sprint/tests.log`).
Direct bundles now share the release source-cleanliness guard. The owner then
requested implementation only and will test independently. No further agent-run
tests, scans or provider acceptance are authorized by that handover. The subsequent
owner-mode preparation helper is IMPLEMENTED_UNVERIFIED; it has not been executed.
No new final acceptance records or stable release are claimed.

## Production preparation — 10 October 2026

- `6a1d362`: refreshed Kali operations/upgrade/restore/rollback (2.331 s), actual
  full-storage recovery (0.274 s), full source/HTTP/queue load (7.266 s) and isolated
  Chromium (7.999 s) PASS. These are exercise runtimes, not approved service budgets.
- `089cefe`: 181 Kali tests PASS in 12.325 s; full CI run 38041422050 PASS.
  Gitleaks 8.24.2 positive/clean controls and sandbox checks PASS; one live OSV
  query returns ten advisories. No provider AI was called.
- `1d35d63eb764e2481d7350e94f8d41476e92664e`: 181 Kali tests PASS in 14.272 s;
  [CI run 38041663352](https://github.com/Het28091/Cyber-scan/actions/runs/38041663352)
  PASS, including offline preparation/install across the Linux/Python matrix.
  The actual Kali candidate archive was verified, rebuilt from local wheels,
  installed and scanned under inherited seccomp denial; both PDF reports pass.
  Host pip settings were deliberately pointed at an unusable remote source and
  required a virtualenv; isolated preparation/install still succeeded offline.

[Copied evidence](evidence/production-kali-oct10.json) records commits, checks and
archive hash. Candidate archive on Kali:
`artifacts/checkpoints/production-oct10/candidate-offline/secaudit-1.1.0-candidate-1d35d63eb764-linux-x86_64-py3.13.tar.gz`.
Full logs remain under `artifacts/checkpoints/production-oct9/` and `production-oct10/`.
The clean test installation was temporary; the candidate archive is retained.

Earlier candidate preparation at `6a1d362` failed to resolve Pillow 12.3.0; later
PyPI metadata confirmed release files exist. We do not claim the exact earlier
environment cause was established. Hashes/versions were not weakened. Gitleaks
transfer timed out, resumed, then its full upstream archive checksum passed before
execution. Checksums from the same upstream are integrity evidence, not an
independent signature. Initial portable tests failed on Windows sandbox temporary
directory permissions; four actual-pip tests passed outside that sandbox, and
Linux acceptance is authoritative. No owner/independent attestation or release
gate was fabricated, and no stable package/tag/publication occurred.

## Separate modes — 9 October 2026

Pipeline follow-up: run 37964117347 at `f078127` passed the new mode journeys
but failed the live OSV/Gitleaks job without stage diagnostics. That failure is
retained as unresolved historical evidence, not relabeled a pass. At `e7480e6`,
the harness emits sanitized stage/counter annotations; live job 37964349440
passes all stages (one OSV request, ten advisories, real Gitleaks controls and
sandbox checks). This later pass does not establish the earlier failure's cause.
On Kali at `e7480e6`, OSV passed but this optional external-scanner check stopped
at preflight because Gitleaks is not installed; no boundary was weakened.
Its VM log is `artifacts/checkpoints/mode-quality/live.log`. The three built-in
mode journeys do not depend on Gitleaks. External-scanner VM acceptance remains
NOT TESTED until that tool is prepared.

Implementation `18fc648`: Kali Python 3.13.12, 177 tests PASS in 9.975 seconds;
CI 37963739961 successful. Eight portable AI/web targeted tests also PASS.
Harness source `15ca6e45ea77a75f54edc5f2692e9a4f54fd87d4`: six actual CLI/PDF
journeys PASS (two offline under seccomp, two owned HTTP, two simulated API).
Required AI truncation correctly produces FAILED while keeping findings/reports.
Original curated corpus: 21 TP, 0 FP, 0 FN; 11 clean cases PASS. VM logs:
`artifacts/checkpoints/mode-quality/tests.log` and `journeys.log`.
See [copied journey evidence](evidence/three-mode-quality-oct9.json) and
[mode-specific limits](THREE_MODE_HANDOVER.md). No live API inference performed.

## Owner DVWA and HTTPS — 9 October 2026

Source `ca13ace488bcc39adec03cf5d971f8c157dc1ecb`: 174 tests PASS on Kali
Python 3.13.12 in 9.755 seconds; four portable targeted tests pass too.
CI run 37962681926 completed successfully. S2-02/S2-05 redirect-cookie repair
retains evidence without widening scope; S3-01/S3-04 actual CLI checks cover
one original HTTP response and two HTTPS responses, independently compared.
TLS validation remained enabled; PDF outputs pass. See
[results and limitations](DVWA_ASSESSMENT.md). No authenticated injection tests,
AI inference or production acceptance claimed.

## API JSON-response option — 6 October 2026

Implementation source `7f8b08f`: full Kali Python 3.13.12 suite, 170 tests PASS in
10.663 s (`artifacts/checkpoints/three-mode/json-mode-tests.log` on the VM).
New tests cover explicit opt-in versus unchanged text mode, metadata minimization,
invalid JSON, unknown finding IDs and unexpected fields. Two portable targeted
tests also passed. Actual provider inference and free-quota status remain NOT TESTED;
the credential-presence check returned false and no real API request was made.

## Owner Kali non-AI modes — 6 October 2026

Source `3d72b5b3a9050921c20a29df7e39c7b07e2060b8`, Python 3.13.12: 168 tests pass,
full source/HTTP/queue load exercise passes, offline CLI completes under inherited
seccomp network denial, and explicit internet-mode web-only CLI completes against
an owned pinned fixture with AI disabled. See [details and copied evidence](THREE_MODE_HANDOVER.md).
No real API call, local-model test or release acceptance is claimed.

## Load, identity and mapping — 6 October 2026

Source `c1cf5989d5561b19df4486b2b3d31da18274900a`: the operations job verifies
the 4,999-file full source scan, twenty owned HTTP pages and ten real queued jobs.
See [measurements, fixes and limits](INDEPENDENT_EXECUTION.md) and
[run 37491440348](https://github.com/Het28091/Cyber-scan/actions/runs/37491440348).
Finding identity/mapping regressions are part of the mandatory main test job.
All **16 mandatory CI jobs PASS**; the optional deployment-specific target job is
skipped. [Durable job/step and measurement evidence](evidence/load-mapping-linux-ci.json)
records the exact source and actual results.
Portable identity/mapping tests also passed on Windows on 2 October; they are not
Linux acceptance. Real providers and owner-machine acceptance remain NOT TESTED
for this source. No publication or release-gate PASS records were created.

## Recovery and limits — 2 October 2026

Source `f02e1e07657b1dd78a01fc69b76d2132f8d0e9ee`: all 16 mandatory jobs PASS in
[CI run 37043137223](https://github.com/Het28091/Cyber-scan/actions/runs/37043137223),
including killed report publication, actual bounded-tmpfs ENOSPC, concurrent queue
admission and default traversal count/byte boundaries. See
[task IDs, runtime failures, commands and limits](INDEPENDENT_EXECUTION.md#recovery-and-limits-checkpoint--2-october-2026)
and [durable job/step metadata](evidence/recovery-linux-ci.json).
Current Kali full-suite outcome is unverified; owner authorized Linux CI continuation
without the VM. Optional deployment target job skipped; real AI providers and owner
acceptance remain pending. No final release-gate acceptance or production claim.

## Provider-independent checkpoint — 2 October 2026

Source `250e82e5b073e94ead33c7fd2dd76a440f40cc68`: **162 Kali tests PASS, no skips**;
real isolated Chromium acceptance PASS; upgrade/restore/rollback PASS; declared
21-rule corpus 21 TP / 0 FP / 0 FN and 11 clean cases PASS. All **16 mandatory CI
jobs PASS** in [run 37039191586](https://github.com/Het28091/Cyber-scan/actions/runs/37039191586).
See [task IDs, commands, runtime, evidence and residual work](INDEPENDENT_EXECUTION.md).
The optional deployment-specific target job was skipped. Real local/API provider
acceptance, owner UAT and exact-commit release gates remain pending. S2–S4 have
not received milestone acceptance and no production release is claimed.

## Spiral 2 — 1 October 2026

Execution is authorized; [SPIRAL2_EXECUTION.md](SPIRAL2_EXECUTION.md) records
current checks and blockers. The PM-only statement below describes the earlier
planning update, not the current implementation work. Spiral 2 is not accepted.

Source `6eda00ad94f796fe1229d22e967e6869e08bf37c`: all 14 mandatory jobs passed in
[run 36807699088](https://github.com/Het28091/Cyber-scan/actions/runs/36807699088).
[Persisted evidence](evidence/spiral2-linux-checkpoint.json) lists individual steps;
the execution record maps results to S2-01/02/03/05. Real local/API provider
acceptance remains NOT TESTED, so S2-04 and the milestone remain BLOCKED.

## Current expanded project — 30 September 2026

Recent feature-first code has not been accepted end to end. The current PM
assessment is [PROJECT_STATUS.md](PROJECT_STATUS.md); new verification work must
record spiral/task ID, exact commit, environment, command, result and evidence
under [FIVE_SPIRAL_PLAN.md](FIVE_SPIRAL_PLAN.md). All entries below retain their
historical scope. This documentation-only PM update ran no tests or provider calls.

## v0.6 live acceptance — passed

100 tests and 93% statement coverage passed; live OSV and Gitleaks positive/clean
controls plus sandbox boundary tests passed. See [CI evidence](evidence/v0.6-live.json).

[Acceptance record](V06_ACCEPTANCE.md) separates actual OSV/scanner execution from
mocked regressions. Full subprocess coverage is collected; the old 69% measurement
missed those processes. The statement coverage gate is 81% with no excluded modules.

## Historical 0.5.0 review response

`python -m unittest discover -s tests -q`: 87 tests pass locally (packaging 26.3).
`node --check secaudit/static/app.js`: passes. Locked packaging 25.0 and the new CI
gates are verified by the linked commit's GitHub Actions run, not by a local clean
install. Local PyPI downloads failed. OSV retry: zero requests/responses; DNS/public
address policy blocked lookup. External scanner binaries remain absent.
See [review response](REVIEW_RESPONSE.md) and [release acceptance issue](https://github.com/Het28091/Cyber-scan/issues/1).

## Historical 0.4.1 verification

Environment: Linux, Python 3.12. Date: 2026-09-22.

| Check | Result |
|---|---|
| `bash run.sh test` | 77 tests passed |
| `bash setup.sh --offline` | Passed after repairing corrupt pip bytecode; see SECURITY_REVIEW.md |
| `node --check secaudit/static/app.js` | Passed |
| Internet-mode pipeline | Controlled OSV response, source analysis, reports and no-AI assertion passed |
| Online disclosure | Only ecosystem/name/version transmitted; deduplication tested |
| Provider failure | HTTP failure, redirects, malformed response, private DNS and pagination tested |
| Offline boundary | Online module rejected; public target IP blocked; existing seccomp tests passed |
| Scope helper | Local DNS pins saved; existing scope overwrite refused |
| Live OSV attempt | Blocked at DNS/public-address policy; correctly NOT TESTED, 0 requests sent |
| Local web / internet mode | Live synthetic server: 2 assets, 6 candidate findings, AI disabled |
| Real source assessment in internet mode | Completed with 5 expected synthetic findings and explicit OSV failure |
| Hardened request/queue/recovery paths | 26 new regression tests passed |
| Documentation links | All local Markdown link targets resolved |
| `make doctor` / `make demo` | Passed; 5 expected source findings |
| Dashboard API | Authentication, Host, CSRF, job completion and PDF download regression tests passed |
| Windows | Removed from supported scope and CI |
| Browser UI | Not newly verified; browser executable unavailable |
| External scanners | Actual binaries/isolation not verified on this host |

Tests use local synthetic targets and controlled provider fixtures. Real internet
access was attempted only for the advisory API, not a scan against a public target.
Prior 0.3 verification covered generated PDFs and disconnected bundle installation.
The 0.4.1 suite continues to exercise PDF output and offline core bundle installation.
Do not interpret fixture verification as external-service or production certification.

Prior release GitHub CI completed successfully. The new release CI status is tracked
in GitHub Actions after publication; local results above were executed before upload.
## Unreleased expanded changes

See [the expanded ledger](EXPANDED_IMPLEMENTATION.md) for portable test results,
new acceptance commands and unverified Linux/provider/browser gates. The historical
release results above do not validate the expanded changes.
