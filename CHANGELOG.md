# Changelog

## 0.3.0 — 2026-09-22

- Interactive dashboard with authenticated job submission, ZIP uploads, cancellation, finding exploration and available-report downloads.
- Local PDF reports with embedded fonts; versioned NIST CSF/WSTG evidence mappings.
- Integrity/freshness-checked advisory snapshots and npm lockfile inventory.
- Optional isolated scanner adapters; real tool validation remains outstanding.
- Source-inclusive offline bundle with explicit locked-wheel preparation.
- Fixed dependency/external-module CLI dispatch; expanded regression tests.
- Updated setup, usage, architecture and capability documentation.


## 0.2.0 — Windows-first launchers

Added Windows setup/run entry points using WSL2 Ubuntu, explicit prerequisite
installation, automatic per-project virtual environment creation, offline setup,
Windows path translation and Linux setup/run scripts. No scanner-time downloads.
Added five setup tests and a Windows PowerShell syntax CI job. Linux verified;
Windows execution remains unverified. Original capability gaps remain.

## 0.1.0 — 2026-09-21

Initial offline assessment core: CLI, preflight, source heuristics, fixed-IP scoped
HTTP checks, optional AI adapters, normalized findings, local exports, authenticated
read-only dashboard, partial-state recovery and checksum-verified zipapp bundles.

This is a partial implementation of the broader design. External scanners, vulnerability
databases, PDF export, full framework mapping, active checks and browser sandboxing
are explicitly unimplemented. See the capability matrix.
