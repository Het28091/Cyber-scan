# Secaudit 1.1.0

Secaudit is a Linux-only, locally operated security assessment orchestration and
evidence application. It coordinates bounded checks and produces reports for review.
This release completes the agreed non-AI workflow; it is not an autonomous pentest
engine or a compliance certification product.

## Changes from 1.0

- Verified Semgrep 1.175.0, Syft 1.52.0 and Trivy 0.74.0 in Bubblewrap.
- Fixed scanner startup/flags, memory-map limits and empty-report handling.
- Verified positive/empty controls, malformed rules, missing/corrupt databases,
  external CycloneDX output and both PDFs through the offline reporting pipeline.
- Added strict Syft/Trivy configuration examples. External tools use the CLI;
  the existing dashboard remains focused on its supported built-in workflows.
- Retained mandatory isolation, explicit preparation, no AI and no automatic target rescan.

## Included

- Source directories and ZIP inputs, bounded Python/config/secret heuristics,
  Python/npm inventories and explicit incomplete-inventory reporting.
- Scoped passive GET/HEAD crawling, IP pinning, static bearer/cookie authentication,
  coverage reporting and optional package-only OSV advisory lookups.
- Isolated Gitleaks integration verified with the real tool inside Bubblewrap.
- Local authenticated dashboard, queue/cancellation, failure diagnostics, searchable
  findings and downloadable PDF/HTML/Markdown/JSON/CSV/SARIF/CycloneDX evidence.
- Offline bundles with locked wheels, version/platform/commit metadata and checksums.

## Validation

104 regression tests; 94% statement coverage at the accepted implementation baseline.
Ruff, Bandit and dependency advisory gates are mandatory. Real OSV and sandboxed
Gitleaks, Semgrep, Syft and Trivy checks run in CI. All are required before publication. Clean/repeat setup and network-denied bundle installation
passed on Ubuntu 22.04/24.04, Python 3.11–3.14, x86_64.

Real Chromium workflows and axe checks cover eight dashboard states. Automated
accessibility checks reported zero violations; manual-review classifications and
assistive-technology limitations remain documented in ACCESSIBILITY.md.

An owner-authorized assessment of the Grid Guard login page returned HTTP 200,
recorded two low-severity missing-header observations and generated both PDFs.
It used one preflight HEAD and one crawler GET, no credentials, no forms and no AI.
This establishes external transport/reporting acceptance, not backend/login security.
See docs/evidence/v1-external-target.json for dated evidence.

## Install or upgrade

For the source checkout:

```bash
bash setup.sh
bash run.sh dashboard
```

Stop an existing dashboard before upgrading; preserve `runs/` evidence and rerun
setup. Existing target credentials stay in environment variables; never put their
literal values in configuration, reports or GitHub issues.

For a downloaded release bundle, verify `SHA256SUMS`, extract the matching
Linux x86_64/Python-minor archive, and use its `secaudit.pyz`:

```bash
sha256sum --check SHA256SUMS
# Replace BUNDLE_DIRECTORY with the extracted bundle directory.
python3 BUNDLE_DIRECTORY/secaudit.pyz bundle verify BUNDLE_DIRECTORY
python3 BUNDLE_DIRECTORY/secaudit.pyz bundle install BUNDLE_DIRECTORY --destination secaudit-installed
./secaudit-installed/secaudit dashboard
```

The chosen Python interpreter must match the bundle's minor version. Python with
venv/ensurepip and system libseccomp must already be installed. Bubblewrap and
external scanner executables are separate, explicit prerequisites. No system package
installation is attempted by offline bundle installation.

## Known limitations and trust

Built-in detection remains heuristic. No login automation, role comparison,
JavaScript/browser execution against targets, active exploitation or complete
framework/control assessment is included. Real AI providers remain unverified and explicitly experimental. External scanner
acceptance covers the pinned releases and bounded fixtures documented in ADAPTERS.md. Other distributions and ARM64 are unverified.

Bundles are unsigned: SHA-256 detects corruption, not publisher authenticity. The
release source commit and CI record provide traceability, not a signature guarantee.
No findings is not proof of security; successful assessments retain explicit limitations.

## External scanner configurations

After explicit installation of the pinned tools and Bubblewrap, use:

```bash
bash run.sh scan --config config/semgrep.json
bash run.sh scan --config config/syft.json
# Edit config/trivy.json to point to your explicitly prepared database first.
bash run.sh scan --config config/trivy.json
```

These examples scan `demo/source`; change the source path for your project.
Read ADAPTERS.md for installation/runtime constraints and Trivy DB preparation.
Scanner binaries, Semgrep dependencies/rulesets and Trivy databases are not included
in the core wheel bundles. Dashboard scanner presets are intentionally outside this
release; CLI configuration is the supported interface for external tools.
