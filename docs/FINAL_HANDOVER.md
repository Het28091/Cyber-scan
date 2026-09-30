# Final delivery target — 14 October 2026

**Post-checkpoint owner feedback:** AI enablement/discoverability work resumed.
Visible disabled-mode guidance, `--experimental-ai` startup options and an AI
results panel are implemented but unverified. See [AI_QUICKSTART.md](AI_QUICKSTART.md).

**30 September checkpoint:** feature development is paused for owner testing.
See [TEST_CHECKPOINT.md](TEST_CHECKPOINT.md) for startup commands, expected manual
flows and feedback format. No new tests or debugging were performed to label this
checkpoint working; the latest implementation remains unverified.

Updated 29 September 2026. The owner corrected 25 October as a typo.
**Target: 14 October 2026 (Asia/Kolkata), including AI and non-AI workflows
and the original project goals.** This supersedes the non-AI-only feature freeze.
This is a delivery target, not a guarantee or a scheduled background task.
Implementation proceeds during active work sessions.

Unreleased implementation status and test results are recorded in
[EXPANDED_IMPLEMENTATION.md](EXPANDED_IMPLEMENTATION.md). The gap descriptions
below are the original delivery-plan baseline; use that ledger for subsequent
progress. No expanded acceptance checkbox is closed by fixture-only evidence.
Stable builds and asset collection now enforce the separately prepared evidence
described in [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md). No expanded acceptance
records or new release have been created.

## Baseline and finish line

### Feature-first spiral pass — 30 September 2026

Per the owner's latest direction, prioritize building the remaining project
workflows and defer testing/debugging to a later improvement pass. The latest
dashboard implementation adds guided target scope, login/logout, role probes,
CORS probes, offline browser snapshots, scanner selection and provider setup.
Advanced JSON remains available for response assertions, detailed AI budgets
and static scope authentication. This pass has **not been tested or debugged**.
Completion percentages are not asserted: implementation breadth and verified
acceptance remain separate, and the original brief is still unavailable.

The subsequent remediation pass adds an assessment-level work list in Reports &
evidence, optional due dates on operator reviews, UTC overdue and unassigned
counts, owner/status/due-date filters, and JSON/CSV action-plan exports from the
dashboard and CLI. It preserves scanner evidence and the existing revision/retest
requirements. This implementation is also unverified; testing/debugging remain
deferred under the owner's spiral-development direction.

The following detection pass implements JSON OpenAPI security/transport declarations
and selected Kubernetes workload isolation settings. Findings include JSON-pointer
evidence and enter the existing remediation/report pipeline. See
[DECLARATION_CHECKS.md](DECLARATION_CHECKS.md) for the rule catalogue and unsupported
cases. This pass has not been tested or debugged and closes no acceptance gate.

The reusable-setup pass adds named assessment profiles, revision-controlled
updates/deletions, loading into the advanced editor, and a readable configuration
summary. Consent and ZIP data are not retained. Saving does not start an assessment
or establish readiness. See [ASSESSMENT_PROFILES.md](ASSESSMENT_PROFILES.md).
This further feature-first implementation remains unverified.

v1.1.0 is the published Linux non-AI baseline. Its recorded 104 tests, 94%
coverage and 14 acceptance jobs validate that release, not the expanded scope.
The original project is not complete merely because v1.1 shipped.

Keep Linux-only setup, automatic virtual environments, dependency preflight,
optional preparation downloads, scoped internet access without AI, and strict
offline operation. Add optional local-model and API-model workflows without
requiring a model or API key for non-AI use.

## Required work and acceptance

| Workstream | Current gap | Required evidence |
| --- | --- | --- |
| Non-AI foundation | Owner-machine feedback pending | Clean installation, deterministic scanning and complete reports without any model or provider credential |
| Local AI | Experimental provider, fixture-tested; no dashboard controls | Real local model through preflight, scan and report; missing model, timeout, malformed output and cancellation tests |
| API AI | Experimental compatible-provider code; live path unverified | Real configured provider with explicit data disclosure, environment-based credentials, budgets, redaction and failure-policy tests |
| AI trust boundary | Existing metadata-only suggestions are not the complete original AI workflow | Document each supported AI function; evidence-linked outputs, untrusted-content tests, no unsupported finding confirmation or AI-issued shell execution |
| Dashboard | Non-AI modes only; external scanner presets are CLI-only | Tested provider selection/configuration, scanner presets, readiness, failures and report provenance |
| Authentication and state | Static scoped credentials only | Test-account login/session lifecycle, expired credentials and role comparisons against controlled applications |
| Browser and active checks | Dashboard browser tests do not scan applications | Scoped target-browser workflow and bounded non-destructive checks, positive/negative controls and request limits |
| Detection breadth | Built-in heuristics and verified adapters do not provide comprehensive detection | Coverage matrix and positive/clean controls for selected web/API, source, dependency, TLS and configuration checks; quantify gaps |
| Workflow and reporting | Existing mappings are partial | Original-brief requirement traceability, assessment stages, evidence/remediation/retest workflow and explicit NIST/OWASP/MITRE mapping coverage |
| Delivery | No expanded-scope release exists | Updated instructions, owner-machine acceptance, mandatory CI, versioned source/bundles/checksums and handover |

The first implementation batch is provider hardening and real local-AI acceptance,
followed by API-provider acceptance and dashboard integration. Do not enable an
experimental mode merely by removing its gate.

Reconcile the original master brief against this matrix before marking final
completion. Requirements discovered there remain tracked; they are not silently
dropped to meet the date. MITRE ATT&CK mapping is not itself an execution sequence,
and framework mappings do not constitute compliance certification.

## Target schedule

| Window | Planned outcome |
| --- | --- |
| 29 September–3 October | Requirement traceability, AI provider hardening and real-provider acceptance; incorporate owner installation feedback |
| 4–8 October | Dashboard integration, authentication/session/role workflows, scoped browser and bounded active checks |
| 9–11 October | Detection and framework coverage reconciliation; end-to-end tests and reporting |
| 12–13 October | Release-candidate freeze, security/regression/installation checks and owner retest |
| 14 October | Final acceptance and versioned handover if required gates pass |

These dates express priority, not completed work. Surface blocked requirements
early with impact and the smallest needed owner input. Do not describe incomplete
features as complete or silently reduce scope. Existing release tags remain intact.

## Inputs that may become necessary

A real API-provider acceptance run requires a supported endpoint/model and a
credential supplied securely in the execution environment, never in chat or Git.
Local-model acceptance requires a suitable runtime/model and sufficient hardware.
Authenticated tests use controlled fixtures first; deployed application testing
needs dedicated test accounts and allowed actions. The earlier read-only Grid Guard
acceptance does not authorize unrelated state-changing tests.

## Owner acceptance checklist

Record PASS / FAIL / NOT TESTED for each applicable item. Do not mark missing
external-tool installation as successful integration coverage.

1. From the source checkout, run `bash setup.sh`; record distribution, architecture
   and `python3 --version`. Setup completes or gives an actionable prerequisite error.
2. Run `bash run.sh scan --config config/offline.json`. The synthetic local
   assessment finishes and records findings/coverage/limitations.
3. Run `bash run.sh dashboard`; sign in using the locally printed session
   credentials. Do not include the password in feedback.
4. Open a report, search findings, and download technical/executive PDFs and JSON.
   Confirm the downloads open and correspond to the selected run.
5. Submit a small owned source directory or ZIP. Check completion, report access,
   and that an invalid input produces a useful error.
6. On a sufficiently long local job, check cancellation and its final status.
   If the job finishes before cancellation, record NOT TESTED, not PASS.
7. Stop and restart the dashboard. Existing evidence remains available.
8. Where installed, use the documented Semgrep/Syft/Trivy CLI configurations.
   Record tool versions and prerequisite failures separately. Trivy requires a
   previously prepared database; missing/corrupt data must not appear clean.
9. Public-target or authenticated assessment is optional and requires an explicit
   scope and authorized target. Keep credentials in environment references.
   No additional Grid Guard traffic is required for final handover.

## Compact feedback format

Copy only the relevant fields into the conversation:

- Release/commit:
- Linux distribution and architecture:
- Python version:
- Command or UI action:
- Expected result:
- Actual result and exact error:
- Reproduces consistently:
- Redacted screenshot/log excerpt:

Never attach passwords, bearer/cookie values, private source, or unredacted reports
to a public GitHub issue. Send only the minimum information needed to reproduce.

## Usage-efficient implementation

Batch related fixes into one pass. Run targeted checks for the changed behavior,
then the required full CI at the release checkpoint. Documentation-only updates do
not require repeated manual full-suite runs. Avoid status-only polling, repeated
external scans and cosmetic redesigns. A failing mandatory release gate blocks
publication; efficiency does not justify removing safety or correctness checks.


## Expanded final acceptance

- [ ] Original-brief requirements mapped to implementation and evidence.
- [ ] Non-AI offline and internet modes verified independently of AI.
- [ ] Real local-model and API-model workflows verified end to end.
- [ ] AI/dashboard failure handling, redaction and disclosure verified.
- [ ] Authenticated, role, browser and bounded active workflows verified.
- [ ] Detection and framework coverage documented with explicit unsupported cases.
- [ ] Owner-machine blockers resolved and required release gates pass.
- [ ] Final tag, downloadable assets, documentation and checksums agree.

No scanner can guarantee discovery of every vulnerability or automatic compliance.
Any unresolved requirement remains visible and prevents an unqualified claim that
the full original idea is finished.
