# Final delivery target — 14 October 2026

**PM update, 30 September:** use [FIVE_SPIRAL_PLAN.md](FIVE_SPIRAL_PLAN.md) for the
current development sequence and [PROJECT_STATUS.md](PROJECT_STATUS.md) for
completion status. Spiral 1 has its implementation handover; Spirals 2–5 cover
functional repair, security/quality, operations and release. The date is at risk
and must be reforecast after the Spiral 2 baseline; gates take precedence.

Updated 30 September 2026. The owner confirmed that this document and SCOPE.md
are the complete **first spiral round** requirements. The separate original brief
is no longer a round-one input blocker. The 14 October target remains a target,
not a guarantee or a scheduled background task.

**First-round implementation is assembled; final acceptance is not complete.**
The first-round handover was unverified under the owner's feature-first direction.
The owner subsequently authorized Spiral 2 testing and repair; see
[SPIRAL2_EXECUTION.md](SPIRAL2_EXECUTION.md) for exact current evidence and blockers.
[ROUND_ONE_HANDOVER.md](ROUND_ONE_HANDOVER.md) is the requirement
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
counted as completed. Testing/debugging start in Spiral 2; security, operations
and final acceptance continue through Spirals 3–5 under the production plan.

## Target schedule and milestone control

The previous calendar buckets are superseded by the risk-driven five-spiral plan.
The 14 October 2026 date remains an aspiration, not an accepted delivery forecast.

| Spiral | Current state | Exit decision |
| --- | --- | --- |
| 1 — bounded prototype | Implementation handover assembled; unverified | Carry acceptance debt visibly into S2 |
| 2 — functional integration | Next, not started | Core journeys, real providers and current regression evidence |
| 3 — security and detection quality | Planned | Boundary assurance, corpus results and reviewed risks |
| 4 — operational reliability | Planned | Recovery/restore/upgrade and measured resource budgets |
| 5 — release and owner acceptance | Planned | All ten exact-commit gates, owner go/no-go and matching artifacts |

The initial remaining effort assumption is 12–21 focused developer-days plus
external waits/review, not a promise. Reforecast after S2-01 and at each spiral
exit. Do not reduce acceptance criteria to fit a date. Detailed tasks, owners,
dependencies and completion rules are in FIVE_SPIRAL_PLAN.md.

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
