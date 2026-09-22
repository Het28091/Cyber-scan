# Capability matrix — 0.4.1

The original brief is a design target. This release implements a usable bounded
assessment workflow; it does not satisfy every advanced capability in that brief.

| Capability | Implemented boundary | Verification |
|---|---|---|
| Internet / no AI | Scoped public targets plus optional OSV; AI rejected | Policy and provider fixtures; live OSV blocked here |
| Linux automatic setup | venv and hash-locked PDF packages | See verification record |
| Local dashboard | Overview, jobs, upload, search, detail, coverage, downloads | HTTP integration; visual status in verification record |
| Job queue | Single worker, bounded queue, cancellation, restart interruption | Local tests |
| Source and secrets | Python AST and text heuristics | Synthetic fixtures |
| Configuration | Debug, TLS verification, Docker USER | Heuristics, no general IaC engine |
| API inventory | JSON OpenAPI declarations | No full schema validator or endpoint fuzzing |
| Dependencies | Exact versions from operator snapshot | Integrity/staleness/CLI tests |
| SBOM | Python pins and npm lock v2/v3; optional Syft | Not exhaustive environment inventory |
| Web | Bounded GET crawl, headers, cookie flags, TLS certificate validation | Local HTTP fixture; no full TLS vulnerability audit |
| External tools | Gitleaks/Semgrep/Trivy/Syft isolated adapters | Output fixtures and fail-closed checks only; actual binaries unverified |
| Frameworks | Selected NIST CSF 2.0 and WSTG 4.2 evidence mappings | Referenced official pages; no complete control assessment |
| Reports | HTML, PDF, Markdown, JSON, CSV, SARIF, CycloneDX, retest plans | Generated and parsed; PDF visual check |
| AI | Ollama / OpenAI-compatible, minimized inputs, budgets | Stubs only; no actual provider/model verification |
| Offline bundle | Core zipapp, source, optional locked wheels, checksums | Core offline integration; full wheels status in verification record |
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
