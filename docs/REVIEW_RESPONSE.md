# Review response — 0.5.0

Reviewed 2026-09-22 against the supplied assessment of commit `9a4c620`.
Secaudit is an assessment orchestration and evidence tool for Linux. Its built-in
checks provide a baseline; they do not replace a mature SAST engine or a penetration
test. Product limitations are not automatically exploitable HIGH vulnerabilities.

## Decisions and implementation

| Review item | Assessment and action |
|---|---|
| H1: detection depth | Accepted limitation. Repositioned the README around scope, orchestration, review and evidence. External adapters remain explicit opt-ins until real isolation/tool verification passes; silently making unavailable tools default would mislead users. No taint engine, TLS configuration analyzer or broad JS/TS engine is claimed. |
| H2: verification debt | Confirmed. A fresh OSV attempt failed before sending any request (DNS/public-address policy); no bypass used. Real scanner binaries are absent. [Issue 1](https://github.com/Het28091/Cyber-scan/issues/1) records owner and acceptance criteria and blocks promoting these integrations as verified. |
| H3: authentication | Accepted future capability, not added as a token field in a scope file. [Issue 2](https://github.com/Het28091/Cyber-scan/issues/2) specifies role isolation, credential references, redirects, login-expiry detection and browser acceptance. |
| H4: dependency inventory | Replaced the narrow requirements regex with `packaging.Requirement`. Extras, markers, hash continuations and normalized names are supported. npm lockfile versions 1–3 and shrinkwrap are parsed. Unresolved ranges, URLs, includes, links, malformed records and missing parser are counted. Strict dependency scans fail on observed inventory gaps. |
| M1: secret heuristics | Accepted limitation. No claim of entropy/dataflow analysis or complete secrets coverage. A fixture-aware suppression design and real Gitleaks validation remain needed; suppressing every test directory would conceal real credentials. |
| M2: DNS/performance | Validated addresses cached per host/port within a Scope; every path/exclusion is still checked. Connections always dial literal validated pins, never a later DNS answer. Conservative sequential traffic and budgets remain intentional. Resolver timeout and large-site crawling remain limitations. |
| M3: job retention | Terminal uploads/configs/scopes are removed; startup handles interrupted and orphan inputs. Keep the newest 200 valid terminal summaries, retaining active jobs and all assessment reports. Arbitrary corrupt/operator-created files are not automatically deleted. |
| M4: diagnostics | Job API and UI expose exit code, safe failure category and preflight component statuses. Raw stdout/stderr remain discarded to avoid leaking source or credentials. Audit records now include assessment start, module coverage snapshots and finish. This is not a real-time tracing system. |
| M5: CI | SHA-pinned GitHub Actions, Ruff correctness checks, Bandit high-severity/high-confidence gate, pip-audit and coverage reporting. CI tool versions are pinned; their transitive dependencies are not yet hash-locked. No mypy or coverage percentage gate is claimed. |
| M6: report read race | The operator-owned/same-UID boundary is documented next to the checks. Symlink checks remain useful accident protection, not a same-account security boundary. |
| M7: AI | Both AI modes and Provider construction require `SECAUDIT_EXPERIMENTAL_AI=1`. Dashboard stays non-AI. This runtime opt-in is a feature gate, not a separate build artifact or a claim of provider verification. |
| L1: dedup | Existing dedup used a full SHA-256, not the short display ID. Fingerprint now also includes role and observation description; distinct same-line observations survive. Cross-scanner identical observations still merge evidence. Display IDs expanded to 128 bits. IDs change for new scans; old reports remain readable. |
| L2/L3: redaction | Conservative email redaction remains. Repeated linear passes are not by themselves O(n²); no benchmark in the review establishes that complexity. Redaction performance and configurable evidence policies remain future work. |
| L4: queue race | Not reproduced: submit already holds an RLock over capacity check, persistence and enqueue, with an exclusive dashboard owner lock. Capacity accounting now uses uncapped history rather than the 200-row display list. |
| L5/L6: limits/signatures | Fixed dashboard bounds and unsigned bundles remain explicit limitations. A signing identity, key/attestation verification and distribution workflow are required before claiming authenticated bundles. |
| Repository identity | Product naming is Secaudit throughout the introduction. Repository URL remains Cyber-scan; rename, topics, description and tagged-release management are not exposed by the connected repository tools used here. No release/tag or rename is claimed. |

## Inventory contract

`inventory.json`, run JSON, technical reports and coverage events expose counts for
each recognized manifest: total, exact pins, unresolved, invalid, unsupported and
conditional. The first 50 issue reasons are retained without raw requirement text.
Counts describe **recognized declarations**, not total installed packages or the
entire project. Unsupported ecosystems/manifests and undiscovered includes remain
outside that denominator. Empty manifests do not prove complete inventory.

Markers are not evaluated against the scanner host: conditional pins are included
conservatively and counted. Extras are parsed but their transitive dependencies are
not inferred. Version ranges and direct URLs never receive fabricated exact versions
and are not sent to OSV. Exact pins are declarations, not proof of installation.
`packaging` is hash-locked for normal setup; core-only bundles without it report the
parser as unavailable instead of silently claiming an empty successful inventory.

Parser references: [PyPA requirements API](https://packaging.pypa.io/en/stable/requirements.html),
[PyPI packaging 25.0 files and hashes](https://pypi.org/project/packaging/25.0/#files).

## Verification

87 unit/integration tests passed locally, including 10 new review regressions.
The local interpreter supplies packaging 26.3; CI installs the locked 25.0 parser.
The existing sandboxed offline-bundle and synthetic local HTTP tests remain in the
suite. JavaScript syntax checks passed. A new clean dependency installation could
not be completed locally because PyPI download attempts failed; CI must establish
the locked environment result. CI status is available on the commit's Actions run.

Live OSV: one eligible package, zero requests, zero responses, one failed lookup.
Real Gitleaks/Semgrep/Trivy/Syft: binaries absent. Browser interaction: not verified.
These gaps are tracked, not converted into passing results. No exhaustive security
coverage or production-readiness certification is implied by this review response.
