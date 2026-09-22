# Verification — 0.6.0

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
