# Verification — Linux 0.4.0

Environment: Linux, Python 3.12. Date: 2026-09-22.

| Check | Result |
|---|---|
| `bash run.sh test` | 51 tests passed |
| `bash setup.sh --offline` | Passed with locally installed locked packages |
| `node --check secaudit/static/app.js` | Passed |
| Internet-mode pipeline | Controlled OSV response, source analysis, reports and no-AI assertion passed |
| Online disclosure | Only ecosystem/name/version transmitted; deduplication tested |
| Provider failure | HTTP failure, redirects, malformed response, private DNS and pagination tested |
| Offline boundary | Online module rejected; public target IP blocked; existing seccomp tests passed |
| Scope helper | Local DNS pins saved; existing scope overwrite refused |
| Live OSV attempt | Blocked at DNS/public-address policy; correctly NOT TESTED, 0 requests sent |
| Local web / internet mode | Live synthetic server: 2 assets, 6 candidate findings, AI disabled |
| Real source assessment in internet mode | Completed with 5 expected synthetic findings and explicit OSV failure |
| Dashboard API | Authentication, Host, CSRF, job completion and PDF download regression tests passed |
| Windows | Removed from supported scope and CI |
| Browser UI | Not newly verified; browser executable unavailable |
| External scanners | Actual binaries/isolation not verified on this host |

Tests use local synthetic targets and controlled provider fixtures. Real internet
access was attempted only for the advisory API, not a scan against a public target.
Prior 0.3 verification covered generated PDFs and disconnected bundle installation.
The 0.4 suite continues to exercise PDF output and offline core bundle installation.
Do not interpret fixture verification as external-service or production certification.
