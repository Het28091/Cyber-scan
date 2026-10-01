# Verification record

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
