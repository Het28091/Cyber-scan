# Secaudit — Cyber-scan

An offline-first application security assessment workspace for authorized testing.
Scan a local project or scoped URL, inspect candidate findings in a local dashboard,
and export evidence for remediation and retesting. AI is optional; deterministic
checks work without it.

**Release: 0.3.0.** Windows uses **WSL2 Ubuntu**, Linux runs directly. This is a
bounded assessment platform, not a guarantee of complete vulnerability detection
or a compliance certification. See [capabilities](docs/CAPABILITIES.md) for precise
boundaries and [verification](docs/VERIFICATION.md) for what was actually tested.

## Start on Windows

Clone or download this repository, then open PowerShell in its root:

```powershell
.\setup.cmd
.\run.cmd scan --config config/offline.json
.\run.cmd dashboard
```

Setup installs missing WSL/Ubuntu prerequisites, creates an isolated Python virtual
environment, installs hash-locked PDF dependencies, and runs preflight. Initial
setup requires internet for missing packages. WSL installation may require an
Administrator terminal, restart, and creation of your Ubuntu user; rerun setup afterward.
No Windows Python, Docker, Make, or manual venv activation is needed.

Open **http://127.0.0.1:8765**. Sign in as `operator` with the temporary password
printed in the terminal. Click **New assessment**, select a source directory or ZIP,
and optionally supply an authorized target URL and scope JSON. The dashboard offers
job cancellation, finding search, severity filters, evidence details, coverage and downloads.
All styles and scripts are served locally; there are no CDN or font requests.

```powershell
.\run.cmd scan --source "C:\Projects\My App" --config config/offline.json
.\run.cmd test
.\run.cmd reports
```

For dashboard input, use a WSL path such as `/mnt/c/Projects/My App`, or upload a ZIP.
Windows CLI paths are translated automatically. Reports and the venv stay on the
Linux filesystem. `run.cmd reports` prints the location. WSL localhost forwarding
must be available for the Windows browser. [Windows details](docs/WINDOWS.md).

## Start on Linux

```bash
bash setup.sh
bash run.sh scan --config config/offline.json
bash run.sh dashboard
```

Python 3.11–3.14, venv/pip and libseccomp are required. Setup provisions missing OS
packages on Debian/Ubuntu; other distributions must install them first. Minimum
core preflight thresholds: 128 MiB free memory and 100 MB free output disk. Provision
more for WSL, PDF dependencies, datasets, or external tools.

`make setup`, `make doctor`, `make demo`, `make demo-web`, `make up`, `make test`,
`make bundle`, and `make down` are also available. The dashboard stays in the
foreground; Ctrl+C stops it and cancels its queued/running work.

## What is included

- Python AST checks, literal secret detection, debug/TLS/Docker configuration checks.
- JSON OpenAPI endpoint inventory and missing declared-security candidates.
- Requirements.txt exact pins and npm lockfile v2/v3 component inventory (CycloneDX).
- Offline exact-version advisory matching with integrity and freshness validation.
- Bounded GET crawling, header/cookie checks, HTTPS certificate validation, DNS pins,
  redirect revalidation, exclusions and explicit scope authorization.
- Optional isolated adapters for Gitleaks, Semgrep, Trivy and Syft. These are
  fixture-tested, **not verified against actual scanner binaries in this environment**.
- A persistent local job queue, authenticated dashboard, mandatory preflight, partial
  evidence preservation and report-only recovery.
- Executive and technical PDFs; HTML, Markdown, JSON, CSV, SARIF and retest exports.
- A small, versioned NIST CSF 2.0 / OWASP WSTG 4.2 evidence mapping snapshot.
- Optional Ollama and OpenAI-compatible AI adapters, tested with controlled stubs.

Scanned project code is never installed, imported or executed. Only ZIP archives
are accepted, with traversal, symlink, size and file-count checks. Do not modify an
input tree while scanning. Local Git checkouts are read as files; Git history is
not scanned. There is no browser execution, autonomous exploitation, state-changing
active testing, authenticated role comparison or full container/image analysis.

## A local web assessment

Two terminals, from the project root:

```bash
# Terminal 1: synthetic demo server
bash run.sh demo-server
```

```bash
# Terminal 2: source + web assessment
bash run.sh scan --config config/offline.json --target http://127.0.0.1:3000 --scope scope.json
```

On Windows substitute `.\run.cmd` for `bash run.sh`. The included scope only
covers the synthetic local demo. For another authorized target, create a scope file
with its authorization reference, exact origins/paths, exclusions and allowed IPs.
All DNS answers must match the pins. Preflight makes one HEAD request; the crawl
uses sequential, bounded GET requests. A server 5xx stops the crawl. GET endpoints
must themselves be safe. The client ignores ambient proxies and does not forward
cookies or credentials. WSL's `127.0.0.1` may differ from a Windows-hosted application's
address; configure the correct reachable host explicitly.

## Offline dependencies and external tools

The built-in dependency module needs an operator-supplied normalized advisory
snapshot. It matches **enumerated exact versions only**, not arbitrary version
ranges. Missing data is NOT TESTED, never “zero vulnerabilities.”

```bash
bash run.sh dataset --input your-advisories.json --output data/advisories.json --source https://your-approved-source.example --version reviewed-snapshot-1 --published-at 2026-09-22T00:00:00Z
```

Set `advisory_dataset` in a copy of `config/offline.json`. See
[dataset schema](docs/DATASETS.md) and [scanner adapters](docs/ADAPTERS.md).
Optional scanners require operator-installed tools, local rules/databases, and a
working Bubblewrap sandbox. Preflight never installs or updates anything. A blocked
sandbox prevents scanner execution. `strict: true` requires every selected module.

## Offline installation bundle

On a connected Linux/WSL machine with the same architecture and Python minor version
as the destination:

```bash
bash run.sh bundle prepare --output offline-bundle --download-dependencies
bash run.sh bundle verify offline-bundle
```

Copy the bundle to the offline machine. Python/venv/pip and libseccomp must already
be installed there. From the directory containing the bundle:

```bash
python3 offline-bundle/secaudit.pyz bundle install offline-bundle --destination installed
./installed/secaudit scan --source /absolute/path/to/project --output /absolute/path/to/reports
./installed/secaudit dashboard --output /absolute/path/to/reports
```

Installation uses `pip --no-index --require-hashes` against bundled wheels. No OS
packages, external scanner binaries/databases, AI models or proprietary standards
are bundled. Omitting `--download-dependencies` produces a smaller core bundle;
PDFs then require an already available ReportLab installation. Bundles contain a
source archive so the dashboard can run without the original checkout. The `.pyz`
is the bootstrap/core CLI; use the installed launcher for the dashboard.

Unsigned checksums detect corruption, not publisher authenticity. Transfer bundles
through a trusted channel. Alternatively, populate `wheelhouse/` in a checkout using
`python3 -m pip download --require-hashes --only-binary=:all: -r requirements.lock -d wheelhouse`,
then use `bash setup.sh --offline` or `.\setup.cmd -Offline` on the prepared machine.

## Optional AI

**Offline** is the default. No AI or public internet access is requested during an
assessment. A source-only built-in assessment additionally denies network syscalls.
Target and AI clients enforce pinned destinations; they are not a system-wide firewall.

For **local AI**, install your Ollama model separately and edit `config/local-ai.json`
with its model name and loopback endpoint. The adapter checks `/api/tags` and uses
`/api/chat`. It never downloads models or falls back to a cloud provider.

For **connected AI**, edit `config/api-ai.json` with an approved HTTPS
OpenAI-compatible endpoint, model ID and IP pins. Provide the API key through the
configured environment variable in the Linux/WSL environment. The provider must
support `/models` and `/chat/completions`. Connected AI is explicitly not offline.

```bash
bash run.sh doctor --config config/local-ai.json
bash run.sh scan --config config/local-ai.json
# After configuring provider and credentials:
bash run.sh scan --config config/api-ai.json
```

Only finding IDs, rule IDs and severity for up to ten findings are sent. Source,
evidence, credentials and asset names are excluded. Suggestions are separate from
findings and cannot run commands, change scope or confirm vulnerabilities. Model
responses must match a schema. Budgets apply per invocation; defaults allow two
requests, no retries and one concurrent request. Cost ceilings require configured
prices and remain estimates. `failure_policy: required` blocks on AI failure;
`continue` preserves deterministic analysis. Real providers have not been tested.

## Reports, interpretation and recovery

Each run has a unique folder containing `run.json`, findings JSON/CSV, technical
HTML/Markdown/PDF, executive HTML/PDF, SARIF, CycloneDX, coverage, mappings,
asset inventory, preflight output, audit event and remediation/retest plan.
The dashboard shows only available downloads. `pdf_required: true` makes a missing
PDF renderer block preflight.

Findings are **candidates**, with confidence separate from severity. PARTIAL means
limited checks ran. NOT TESTED means no conclusion can be drawn. Framework mappings
are related evidence, not certification, organizational control verification or a
complete ASVS/ATT&CK checklist. CVSS is unset when no justified vector exists.

```bash
bash run.sh resume RUN_ID
```

Recovery regenerates reports from saved evidence and does not repeat requests.
Do not recover an actively running assessment. Interrupted dashboard jobs are
marked INTERRUPTED after restart; they are not silently resubmitted.

## Troubleshooting

| Symptom | Action |
|---|---|
| Setup requests reboot/user creation | Complete WSL initialization, then rerun setup. |
| POLICY_BLOCKED isolation | Use Linux/WSL2 with libseccomp; external tools also need permitted Bubblewrap namespaces. |
| DATA_MISSING / DATA_STALE | Supply or refresh the local snapshot during preparation; inspect its provenance. |
| Target unavailable | Check its process, origin, path, port, IP pins and authorization file. |
| No PDFs | Rerun setup, or install the prepared locked wheels offline. |
| AI unavailable | Verify endpoint, model and environment credentials in WSL/Linux. |
| No findings | Read coverage and events; this is not evidence of complete security. |

## Development and GitHub

```bash
bash run.sh test
node --check secaudit/static/app.js
```

Tests use only synthetic fixtures, temporary files and local servers. GitHub Actions
runs Python tests plus a PowerShell syntax job; syntax validation is not a Windows
WSL integration test. See [verification](docs/VERIFICATION.md),
[architecture](docs/ARCHITECTURE.md), [security policy](SECURITY.md), and
[contributing](CONTRIBUTING.md).

Repository: https://github.com/Het28091/Cyber-scan

Never commit real target reports, uploaded projects, credentials, database snapshots,
model weights or virtual environments. The included demo uses synthetic evidence.
MIT license covers this project's code; dependency/tool licenses remain separate.
