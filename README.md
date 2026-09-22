# Secaudit — Linux security scanner

**0.4.1 · Linux only · First milestone: a working non-AI assessment pipeline.**

Assess authorized application URLs and local source projects, review candidate
findings in a local dashboard, and export technical/executive reports.
Internet access does not require an AI model or API key.

[Project scope](docs/SCOPE.md) · [Progress](docs/PROGRESS.md) ·
[Verification](docs/VERIFICATION.md) · [Capabilities](docs/CAPABILITIES.md) · [Security review](docs/SECURITY_REVIEW.md)

## Quick start

From the repository root on Linux:

```bash
bash setup.sh
bash run.sh dashboard
```

Setup creates `.venv`, installs hash-locked dependencies and runs preflight. On
Debian/Ubuntu it can install missing Python/venv/libseccomp prerequisites through
apt; sudo may be requested. Other Linux distributions must provision these first.
Use Python 3.11–3.14. Initial setup needs internet for missing packages. There is
no model download or AI service to configure.

Open **http://127.0.0.1:8765**, use username `operator` and the session password
printed in the terminal. **New assessment** accepts a Linux source path or ZIP and
an optional authorized URL/scope file. The default dashboard mode is **Internet
access · No AI**. Search findings, inspect evidence, cancel jobs and download reports.
All UI assets are local. Ctrl+C stops the dashboard.

Windows launchers, path conversion and Windows CI have been removed. Previous
releases remain in Git history. To migrate, use a Linux checkout and rerun setup;
existing report evidence is not deleted. WSL-specific installation is no longer a
supported project workflow.

## Two non-AI modes

| Mode | Target access | Dependency lookups | AI |
|---|---|---|---|
| `internet` | Explicitly authorized local or public targets | Optional OSV HTTPS lookup | Rejected |
| `offline` | Explicitly scoped local/private targets; public IPs blocked | Operator-supplied local dataset only | Rejected |

“No AI” is not the same as “offline.” The first milestone is a locally running
scanner that **may use the internet without AI**. Source-only built-in offline
scans also block network syscalls. Target hostname resolution uses the configured
system resolver; use IP-literal private targets or an isolated local resolver for
an entirely disconnected lab.

Internet mode retains target authorization, origin/path restrictions, exclusions,
IP pins, rate and size limits, redirect checks and TLS verification. It does not
authorize scanning unrelated sites or silently install tools during assessment.
External scanner adapters remain network-isolated. Internet access is through the
reviewed target client and the selected advisory provider, not arbitrary shell access.

## Run the supplied demo

```bash
# Fully local source demonstration; no AI or online lookups
bash run.sh scan --config config/offline.json

# Source checks plus online package advisories; no AI
bash run.sh scan --config config/internet.json
```

The demo dependency is synthetic and is not expected to have real advisories.
For a local web demo, start `bash run.sh demo-server` in another terminal, then:

```bash
bash run.sh scan --config config/internet-web.json --target http://127.0.0.1:3000 --scope scope.json
```

## Assess your authorized target

Create a scope file using your actual authorization reference and URL:

```bash
bash run.sh scope --origin https://your-authorized-app.example/ --authorization "Your permission or engagement reference" --exclude https://your-authorized-app.example/logout --output my-scope.json
```

Replace the example domain first. This command resolves current IP pins and creates
a file; it neither scans the target nor proves ownership. Review the generated
origins, exclusions, IPs and budgets before scanning. It refuses to overwrite an
existing scope record. Then run:

```bash
bash run.sh scan --config config/internet-web.json --target https://your-authorized-app.example/ --scope my-scope.json
```

For source and web together, use `config/internet.json` and add
`--source /absolute/path/to/project`. For web-only, use `internet-web.json` so the
bundled demo source is not included. DNS changes require reviewing and replacing
pins; mismatches are blocked. Ambiguous semicolon paths, encoded delimiters,
invalid UTF-8 and port zero are rejected, including applications that intentionally
use those URL forms. Exclude logout and other state-changing GET routes.

Preflight sends one scoped HEAD request. Web checks use sequential GETs; no form
submission or script execution. Defaults are 10 crawl requests and 30 seconds.
Server 5xx stops crawling. Ambient proxies and automatic credential forwarding are
not used. HTTPS certificates and hostnames are verified.

## Online dependency advisories

`online_dependencies` in `config/internet.json` queries the fixed endpoint
`https://api.osv.dev/v1/query`. **Package ecosystem, name and version leave the
machine.** Source files, paths, credentials, HTTP captures and reports are not sent.
Omit this module if your package identities must remain private. It is invalid in
offline mode. OSV access is independent of permission to scan your target.

Supported inventory: exact requirements.txt pins and npm package-lock v2/v3 entries.
Queries are deduplicated and limited to 25 packages by default (maximum 100), with
response-size and time bounds, no retries and no redirect following. The provider
must resolve to public IPs. Failures, skipped packages and paginated responses are
reported as incomplete coverage. Missing network access is never a clean result.
Findings cite the advisory and require manual validation. MEDIUM is a provisional
triage priority, not a computed CVSS score. Runtime updates do not alter installed tools.

Official API contract: https://google.github.io/osv.dev/post-v1-query/

**Verification limit:** the OSV adapter passes controlled response tests, but the
live lookup was blocked by this development environment's DNS/public-address policy.
A successful real OSV query on an unrestricted Linux machine is still outstanding.

For disconnected dependency checks, see [local datasets](docs/DATASETS.md).

## Outputs and boundaries

`runs/<run-id>/` contains PDF/HTML/Markdown reports, JSON/CSV findings, SARIF,
CycloneDX inventory, coverage, framework mappings, preflight output and a retest plan.
Reports state the mode, AI status and online-query outcomes. `bash run.sh reports`
prints the output directory. Failed/interrupted scans preserve available checkpoints.

```bash
bash run.sh resume RUN_ID
```

Recovery regenerates saved reports without repeating checks. Do not recover an active
scan. Recovery changes only the selected run. Only one dashboard may own an output
directory at a time. The dashboard executes one job at a time; interrupted jobs are not automatically
resubmitted. Source code and ZIP contents are never installed or executed.

Findings are candidates, not proven exploits. PARTIAL indicates limited checks;
NOT TESTED indicates unavailable coverage. No findings is not proof of security.
There is no browser-driven scanning, authenticated role comparison, automated
exploitation or full compliance certification. The selected NIST CSF/WSTG mappings
are evidence context only. See [the capability matrix](docs/CAPABILITIES.md).

## Offline setup and portable bundles

With prerequisites and locked wheels already present in `wheelhouse/`:

```bash
bash setup.sh --offline
```

Prepare a portable bundle on a connected Linux machine:

```bash
bash run.sh bundle prepare --output offline-bundle --download-dependencies
bash run.sh bundle verify offline-bundle
```

On matching Linux architecture/Python minor version, with Python/venv/libseccomp
already available:

```bash
python3 offline-bundle/secaudit.pyz bundle install offline-bundle --destination installed
./installed/secaudit scan --source /absolute/path/to/project --output /absolute/path/to/reports
```

The installer uses bundled wheels without downloads. Unsigned checksums detect
corruption, not publisher authenticity. OS packages, optional external tools,
models and third-party vulnerability databases are not included.

## Development and troubleshooting

```bash
bash run.sh doctor --config config/offline.json
bash run.sh test
node --check secaudit/static/app.js
```

- `POLICY_BLOCKED`: inspect target scope, IP pins and Linux isolation prerequisites.
- OSV unavailable: inspect DNS/firewall access to `api.osv.dev:443`; do not disable TLS
  verification or public-address checks to force a connection.
- Offline public target rejected: use `internet` mode for an authorized public target.
- Missing PDF renderer: rerun setup or install the prepared locked wheels offline.
- External tools unavailable: see [adapter requirements](docs/ADAPTERS.md). Isolation
  is mandatory; installation alone does not establish compatible execution.

CI runs on Ubuntu; tests use synthetic local targets and provider fixtures, not public
scan targets. Optional AI backend code is retained for later development, but is
excluded from the first milestone and from the dashboard's available modes.

MIT license. Do not commit real target reports, uploads, credentials or private package
inventories. [Security policy](SECURITY.md) · [Architecture](docs/ARCHITECTURE.md)

## Adversarial verification

The 0.4.1 review added 26 regression tests: **77 tests pass locally**. Scope validation,
HTTP error handling, upload cleanup, recovery and evidence preservation were hardened.
See the [review](docs/SECURITY_REVIEW.md) for findings and remaining risks. These
checks do not establish complete edge-case coverage or production certification.
