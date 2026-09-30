# Final delivery target — 14 October 2026

Updated 30 September 2026. The owner confirmed that this document and SCOPE.md
are the complete **first spiral round** requirements. The separate original brief
is no longer a round-one input blocker. The 14 October target remains a target,
not a guarantee or a scheduled background task.

**First-round implementation is assembled; final acceptance is not complete.**
The latest work has not been tested or debugged, following the owner's feature-first
direction. [ROUND_ONE_HANDOVER.md](ROUND_ONE_HANDOVER.md) is the current requirement
traceability and handover. Earlier test results apply only to their recorded code.

v1.1.0 remains the published baseline. This working tree contains expanded code;
it is not a new stable release. No final tag or expanded acceptance record is
claimed. [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md) describes the exact-commit
gates and explicit publication path.

## Required work and acceptance

| Workstream | First-round implementation | Remaining evidence |
| --- | --- | --- |
| Non-AI foundation | Linux setup, independent offline/internet modes and module/limit selection | Linux regression, installation and owner verification |
| Local/API AI | Gated adapters, startup flag, visible configuration, readiness, credentials, budgets and suggestions | Actual prepared providers, failures, redaction and cancellation |
| AI trust boundary | Metadata-only, schema-validated suggestions linked to existing findings in UI/exports | Untrusted-output and disclosure verification; no autonomous AI scanner claimed |
| Dashboard | Guided and advanced forms, profiles, jobs, retained preflight, reports and triage | Real browser/accessibility acceptance of new controls |
| Authentication and state | Explicit bearer session lifecycle, static credentials, role status/field assertions | Controlled application and expired-credential acceptance |
| Browser and active checks | Pinned static snapshots, isolated renderer, bounded CORS probes | Real Chromium/Bubblewrap acceptance and positive/negative controls |
| Detection breadth | Selected web/API, source, dependency, verified TLS transport and JSON configuration checks | New-rule controls and explicit unsupported coverage review |
| Workflow and reporting | Plans, coverage, reports, operator history, remediation/retest, queued report refresh and partial framework maps | End-to-end evidence and mapping/requirements reconciliation |
| Delivery | Candidate/stable packaging, NOT TESTED evidence scaffolding, acceptance/CI verification, explicit versioned publisher | Unused final version, all exact-commit acceptance, stable bundles and publication |

First-round boundaries are deliberate and explicit: no application JavaScript
browser execution, general OAuth/MFA negotiation, arbitrary business-logic testing,
exhaustive discovery or compliance certification. Those capabilities are not
counted as completed. Testing/debugging and external acceptance form round two.

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

- [ ] Confirmed round-one requirements mapped to implementation and acceptance evidence.
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
