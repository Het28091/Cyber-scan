# Architecture and security boundaries

Python's standard library minimizes offline installation complexity and removes
third-party Python resolution from the core execution path. Linux/libseccomp is an
explicit system prerequisite. Configurations are typed dataclasses with allowlisted
fields and validation; no eval or dynamic import comes from configuration.

| Module | Responsibility |
|---|---|
| cli | Commands, run lifecycle, cancellation, bounded synchronous execution |
| config | Typed configuration and disclosure-policy validation |
| preflight | Runtime, evidence, kernel filter, scope and optional AI readiness |
| security | Canonical URLs, IP scope, redaction, archives, atomic files, seccomp |
| network | Fixed-IP HTTP/TLS transport and bounded GET inventory |
| scanners | Read-only syntax and pattern checks; no source execution |
| models | Findings, timestamps, conservative deduplication |
| store | SQLite v1 migration, checkpoints and interrupted-run recovery |
| reporting | Escaped local reports and structured exports |
| ai | No-tools provider boundary, schema checking, data minimization |
| dashboard | Loopback authenticated dashboard and CSRF-protected job API |
| bundle | Zipapp/source/wheel preparation, checksum verification and offline installation |

## Trust model

The operator owns configuration and grants the source/target scope. All source
content, pages and findings are untrusted. The application never imports target
modules, executes target instructions, submits forms or evaluates model output.
Mutating dashboard endpoints require both the session authorization and an exact local Origin plus a per-process CSRF token. Uploads are bounded and passed to the reviewed archive extractor. A single job worker launches only the fixed scanner entry point, with arguments passed as a list.
Basic authentication uses a new per-process random password. Host validation protects
against ordinary DNS rebinding, and no CORS headers or cookie session is provided.
Authentication does not protect against a malicious process with the same OS user.

The source-only CLI installs an irreversible seccomp network denial before reading
source. Preflight probes the policy in a child first. Scans with target or AI access
use the built-in fixed-IP client and validated allowlists. Proxies, automatic redirects,
remote report assets and implicit credentials are absent. That client is a code-level
boundary, not a replacement for kernel isolation for any future subprocess adapter.

Source trees should be immutable during scanning. Symlink files and directories
are skipped; final file descriptors use O_NOFOLLOW, O_NONBLOCK and regular-file checks.
A malicious concurrent OS user may mutate ancestor directories; filesystem snapshot
isolation against that adversary is not claimed. ZIP extraction validates all members
before creating the extraction directory and enforces total expanded bytes.

Redaction is defense in depth, not perfect PII recognition. Built-in findings discard
source snippets and credential values at detection time. Web evidence retains only
header names and missing cookie attributes; no raw captures are saved. Do not include
personal data in filenames or URL paths. Output files are mode 0600, run directories
0700, and writes are atomic. Output directories must be operator-controlled.

SQLite stores partial evidence. A failed scan retains the last checkpoint; a signal
before the first checkpoint may leave no findings. SIGKILL cannot run finalization;
`resume` marks the persisted RUNNING record INTERRUPTED and regenerates reports. It
must only be used after confirming the assessment process is no longer running.
The terminal `COMPLETED_WITH_LIMITATIONS` is not a security pass.

## Additional modules

`jobs` persists queue metadata and owns one bounded worker. `adapters` owns isolated
external subprocesses. `datasets` validates local advisory integrity and freshness.
`frameworks` applies reviewed evidence mappings. `pdf_report` renders locally using
ReportLab and its packaged fonts. Report generation never resolves remote assets.
