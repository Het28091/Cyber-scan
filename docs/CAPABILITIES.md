# Capability matrix — 1.0.0

The original brief is a design target. This release implements a usable bounded
assessment workflow; it does not satisfy every advanced capability in that brief.

| Capability | Implemented boundary | Verification |
|---|---|---|
| Internet / no AI | Scoped public targets plus optional OSV; AI rejected | Live OSV passed on Linux CI; see V06_ACCEPTANCE.md |
| Linux automatic setup | venv and hash-locked PDF packages | Eight clean/repeat-install combinations passed on x86_64 |
| Local dashboard | Overview, jobs, upload, search, detail, coverage, downloads | Real Chromium workflow acceptance; desktop/mobile screenshots reviewed |
| Job queue | Single worker, bounded queue, cancellation, restart interruption | Local tests |
| Source and secrets | Python AST and text heuristics | Synthetic fixtures |
| Configuration | Debug, TLS verification, Docker USER | Heuristics, no general IaC engine |
| API inventory | JSON OpenAPI declarations | No full schema validator or endpoint fuzzing |
| Dependencies | Exact versions from operator snapshot | Integrity/staleness/CLI tests |
| SBOM | Quantified Python declarations and npm lock v1/v2/v3; optional Syft | Not exhaustive environment inventory |
| Web | Scoped static bearer/cookie GET/HEAD, headers, cookie flags, TLS certificate validation | Owned local fixtures plus authorized external login page; no full TLS vulnerability audit |
| External tools | Gitleaks/Semgrep/Trivy/Syft isolated adapters | Gitleaks 8.24.2 verified live in Bubblewrap; others fixture-tested |
| Frameworks | Selected NIST CSF 2.0 and WSTG 4.2 evidence mappings | Referenced official pages; no complete control assessment |
| Reports | HTML, PDF, Markdown, JSON, CSV, SARIF, CycloneDX, retest plans | Generated and parsed; PDF visual check |
| AI | Ollama / OpenAI-compatible, minimized inputs, budgets | Explicit experimental gate; stubs only; no real provider verification |
| Offline bundle | Core zipapp, source, optional locked wheels, checksums | Full wheel installs under seccomp network denial; Ubuntu 22.04/24.04 × Python 3.11–3.14 |
| Recovery | Saved evidence/report regeneration | Does not repeat scans |
| Browser / active workflows | Not implemented | Always outside claimed coverage |
| Dedicated-account role comparisons | Not implemented | Manual work required |
| Container image / broad IaC scanning | Not implemented | Dockerfile heuristic only |
| Full ASVS, ATT&CK, SP 800-53, ISO/PCI/SOC/CIS | Not implemented | Do not infer compliance from related mappings |
| CVSS | Null unless justified scoring is added | No invented scores |

All runs retain COMPLETED_WITH_LIMITATIONS when successful. No findings does not
mean secure. Uploaded projects are never executed. Source-only built-in scans without online advisory/AI access use
seccomp; external tools use Bubblewrap with network namespaces and read-only input.
The development host blocks Bubblewrap namespaces, so external tool execution
cannot be validated here and must remain blocked here.
