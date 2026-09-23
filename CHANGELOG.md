# Changelog

## Unreleased — v1.1 verification

- Verified real Semgrep 1.175.0 in Bubblewrap with positive/clean/invalid-rule controls.
- Fixed Semgrep CA-bundle startup, version-probe network flags and address-space compatibility.
- Bounded Semgrep to one worker and added a runnable local-rule configuration example.
- Syft/Trivy verification and v1.1 publication remain outstanding.

## 1.0.0 — Linux non-AI workflow acceptance

- Passed owner-authorized external HTTPS login-page scan and PDF generation.
- Added gated publication of versioned source and four Python wheel bundles.

- Improved dashboard contrast, supporting text sizes and responsive wrapping.
- Added axe accessibility checks across eight browser states and documented bounded review.
- Built downloadable candidate bundles with source metadata, locked wheels and checksums.

- Added real Chromium workflow acceptance and Linux/Python distribution matrix.
- Verified clean/repeat setup and network-denied wheel-bundle installation on eight combinations.
- Fixed JSON report downloads and underscore-containing preflight report URLs.
- Added report byte-integrity regressions and accessible dialog names.
- Removed misleading dashboard version placeholder.
- Owner-authorized external login-page acceptance passed; scoped release gates completed.

## 0.6.0 — Verified integrations and static authentication

- Passed genuine live OSV and real Bubblewrap/Gitleaks acceptance on Linux CI.
- Fixed Gitleaks WASM virtual-address limit and stdout report-path incompatibilities.
- Added scoped static bearer/cookie credentials with environment references, validation,
  redaction, redirect boundaries and explicit rejected-access reporting.
- Added negative failure regressions and subprocess coverage: 100 tests, 93% statements.
- Enforced the 81% coverage gate; retained all other security and dependency gates.
- Recorded live evidence and remaining browser/distribution work for v1.0.


## 0.5.0 — Review response

- Quantified PEP 508 requirements/npm lockfile inventory; strict dependency-gap failure.
- Cached validated DNS pins, job retention/cleanup and safe dashboard diagnostics.
- Feature-gated experimental AI; distinct same-line finding identity (new IDs).
- Added CI correctness, security, dependency and coverage gates; SHA-pinned actions.
- Added 10 regression tests and documented decisions plus live acceptance blockers.


## 0.4.1 — 2026-09-22

- Adversarial hardening: strict scope/URL parsing and resilient malformed HTTP/JSON handling.
- Bounded dashboard connections, exclusive queue ownership and rejected-upload cleanup.
- Targeted recovery and evidence checkpoints across scanner failures.
- Staged advisory validation and non-overwriting snapshot publication.
- 77 passing tests and a documented security review with residual risks.

## 0.4.0 — 2026-09-22

- Linux-only setup, launch and CI; removed Windows/WSL wrappers.
- Non-AI internet mode with scoped public targets and optional OSV package queries.
- Strict-offline public-IP and online-module restrictions.
- Scope creation helper; updated dashboard mode and disclosure text.
- Progress/scope documentation and 51 passing tests; live OSV access remains unverified.

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
