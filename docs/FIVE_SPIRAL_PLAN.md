# Five-spiral production implementation plan

Owner: project owner. Delivery lead: assigned developer. Independent review role:
security/quality reviewer where available. One person may hold several roles,
but identify that limitation; a developer self-check is not independent review.
Baseline and current status: [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Working agreement

Each spiral is a risk-driven loop: agree objective and boundaries → identify the
highest risks → implement or repair → validate on appropriate environments →
record evidence and obtain the milestone decision → update the next spiral.
This replaces the earlier assumption that all remaining work fits into round two.
It does not enlarge the product into a new platform.

Maintain separate implementation and verification states. Suggested task states:
TODO, IN_PROGRESS, IMPLEMENTED_UNVERIFIED, VERIFIED, BLOCKED. A spiral is ACCEPTED
only after its exit criteria are met. Spiral 1 is IMPLEMENTATION_HANDOVER, with
verification deliberately carried forward; it is not a passed production gate.

New feature requests go to a separate change backlog with value, risk, effort,
dependencies and acceptance criteria. Do not start them while critical defects
or the current spiral's exit criteria remain unresolved. Fixes required for the
agreed scope, trustworthy evidence or operational readiness stay in scope.

## Spiral 1 — bounded end-to-end prototype

**State:** implementation handover assembled at `a285628`; recent changes unverified.
**Objective:** assemble the user journey without claiming production readiness.
**Primary risk:** mistaking code presence for proven behavior.

Implemented journey: configure source/target → select non-AI or experimental AI →
scope and preflight → queued bounded checks → findings/coverage → reports → review,
ownership and due dates → retest → report refresh. Profiles and release tooling
are included. See [ROUND_ONE_HANDOVER.md](ROUND_ONE_HANDOVER.md) for boundaries.

**Handover criteria:** every agreed workstream maps to code and explicit limits;
setup and manual-test instructions exist; missing evidence remains visible;
source is retrievable from GitHub. No new development is needed just to re-label
this spiral. Corrections discovered later are tracked against their later spiral.

## Spiral 2 — functional integration and repair

**State:** next; not started. **Entry:** owner starts execution, Linux environment
available for runtime work, current source baseline recorded. Establish access to
real providers early; continue independent non-AI work if either is unavailable.
**Risk:** broad unverified changes may fail basic user journeys.

| ID | Work package | Completion evidence |
| --- | --- | --- |
| S2-01 | Reproduce setup on Linux; establish current test baseline and dependency/tool versions | Fresh setup log, commit/runtime inventory, failing/passing check inventory; no silent skips |
| S2-02 | Repair non-AI scans, ZIP/source/target input, modules/limits and profiles | Offline and internet journeys, malformed inputs, mode transitions, save/load/restart and explicit no-AI transport assertions |
| S2-03 | Repair dashboard job lifecycle and reports | Browser evidence for success, preflight failure, cancellation, restart, review/history, due dates, comparison, report refresh and downloads; keyboard/accessibility checks |
| S2-04 | Exercise prepared Ollama and actual compatible API provider | Real provider identity, model/readiness/inference/report path; missing model/key, timeout, malformed output, budget and cancellation behavior; fixtures tracked separately |
| S2-05 | Update stale regression expectations for intentional UI/behavior changes | Meaningful regression tests for repaired behavior; full existing suite and correctness gates passing; no deletion/weakening of tests to hide failures |

**Exit:** supported core journeys have evidence, no open P0/P1 functional defects,
real local/API paths each have a demonstrated successful run, regressions pass,
and optional prerequisites/failure states are usable. A provider-dependent item
can remain BLOCKED, but then Spiral 2 is not ACCEPTED. Owner sees a working demo
and a remaining-defect list. Evidence is preliminary until final-commit reruns.

## Spiral 3 — security boundaries and detection quality

**State:** planned. **Entry:** stable core from Spiral 2; owned fixtures and prepared
sandbox/scanner/browser tools. **Risk:** false assurance or unauthorized egress.

| ID | Work package | Completion evidence |
| --- | --- | --- |
| S3-01 | Review and verify scope, DNS pins, redirects, Host/CSRF/auth, archive and filesystem boundaries | Threat model with trust boundaries and abuse cases; positive/negative controls for permitted and blocked behavior |
| S3-02 | Verify credentials, AI disclosure, output trust and network isolation | Canary-secret redaction checks across logs/reports/profiles; non-AI never calls AI; offline egress denied; AI text cannot execute or confirm findings |
| S3-03 | Verify bearer lifecycle, roles, CORS and real static-browser isolation | Authorized fixtures including expiry/failed cleanup/partial responses; real Chromium/Bubblewrap with script and network negative controls |
| S3-04 | Establish detection-quality corpus and mapping traceability | Positive and clean examples per supported built-in rule/parser and adapter; TP/FP/FN counts on the declared corpus, duplicate/fingerprint review and mapping references |
| S3-05 | Review dependencies, sandbox failures and error semantics | Current required security/dependency gates; scanner versions recorded; unavailable/partial paths never appear clean; reviewed risk register |

**Exit:** no unresolved critical/high security defect or scope/credential/isolation
boundary failure; every advertised detection family has controlled positive/clean
evidence; all curated must-detect cases pass; corpus-specific FP/FN results and
limitations are published without extrapolating to universal detection. Any lower
risk accepted by the owner has rationale, owner and remediation date. Required
release gates cannot be waived through such risk acceptance.

## Spiral 4 — operational reliability and maintainability

**State:** planned. **Entry:** stable security boundaries and known detection limits.
**Risk:** evidence loss, unbounded resources or a deployment that cannot recover.

| ID | Work package | Completion evidence |
| --- | --- | --- |
| S4-01 | Define and meet operating budgets | Reference Linux hardware recorded; small/representative/near-limit source and target workloads; wall time, RSS, disk/report size and queue observations; budgets approved before acceptance |
| S4-02 | Make persistence and report snapshots reliable | Abrupt termination, full disk, concurrent/stale review edits, interrupted exports and restart exercises; immutable findings retained; incomplete refresh clearly detected or atomically published |
| S4-03 | Add/finish backup, restore and upgrade/rollback procedure | Restore a copy of runs/reviews/profiles and verify identities/content; safe schema/version handling; clean install and upgrade from a supported earlier version; rollback without destructive evidence loss |
| S4-04 | Finish operator diagnostics and runbooks | Actionable preflight/job errors, redacted logs, storage/retention guidance, secret lifecycle, provider/scanner preparation, recovery and support checklist |
| S4-05 | Reduce release-critical fragility | Focused refactoring only where needed for tested reliability, maintained regression coverage and dependency inventory; no unrelated redesign |

**Exit:** at least one completed restore and upgrade/rollback exercise; all documented
input/queue/time bounds behave as specified; no open data-loss/corruption or resource
exhaustion defect; measured performance meets the agreed reference budget. Queue
capacity, 10 MB ZIP cap and existing configured limits are preserved unless an
explicitly reviewed change updates their tests/docs. Do not invent universal
throughput guarantees for user-supplied providers or scanners.

## Spiral 5 — release candidate, owner acceptance and launch

**State:** planned. **Entry:** Spirals 2–4 accepted, release blockers closed and an
unused final version selected before the source freeze. **Risk:** shipping artifacts
whose source/evidence/version disagree.

| ID | Work package | Completion evidence |
| --- | --- | --- |
| S5-01 | Freeze release scope, version and source commit; review notes/license/support policy | Recorded immutable SHA, clean packaged source, reviewed scope and known limitations |
| S5-02 | Rerun final acceptance against that exact commit | All ten `release_gate.py` records genuinely PASS, actual mandatory CI jobs succeed; current Linux/browser/providers/scanners and owner results |
| S5-03 | Build and independently install distributable candidates | Four Linux x86_64 Python 3.11–3.14 stable bundles with matching manifest digest; checksum verification; fresh install, offline prepared install and report smoke verification |
| S5-04 | Owner UAT and explicit go/no-go | Owner completes agreed workflows on intended machine, reviews remaining supported limits and rollback procedure; written release approval |
| S5-05 | Publish through gated path and monitor the launch | Matching tag/assets/notes/checksums, download/install verification, triage contact and an agreed observation window with rollback triggers |

**Exit / production definition of done:** all ten gates PASS for the exact shipped
commit, mandatory CI actually succeeds, no open release-blocking defect, required
operational exercises complete, owner accepts intended use, and published artifacts
match the source. A disabled/skipped check is not PASS. CI green alone is insufficient.
Any source change after freeze invalidates prior exact-commit release acceptance;
create a new candidate and rerun the applicable evidence/gates before publication.

## Acceptance ownership and traceability

| Existing release gate | Prepared during | Final confirmation | Accountable role |
| --- | --- | --- | --- |
| `original_brief` (legacy schema name; confirmed two-document scope) | S1/S2 traceability | S5 | Owner + delivery lead |
| `non_ai` | S2, strengthened S3/S4 | S5 | Developer / quality reviewer |
| `local_ai`, `api_ai` | S2, strengthened S3 | S5 | Developer; owner supplies providers |
| `dashboard` | S2 and S4 | S5 | Quality reviewer / owner |
| `target_workflows`, `target_browser` | S3 | S5 | Developer / security reviewer |
| `detection_frameworks` | S3 | S5 | Security reviewer / owner |
| `owner_machine` | S4 preparation | S5 | Owner |
| `linux_ci` | S2 onward | S5 actual exact-SHA run | Developer |

Gate file structure and publication commands remain authoritative in
[RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md). Additional operational evidence
is linked by the owner-machine/non-AI/detection review checks; it does not replace
or weaken existing mandatory gates.

## Prioritized execution backlog

All S2–S5 IDs above start **TODO**. Next task: **S2-01**. Suggested sequence:
S2-01 → S2-02/S2-03 → S2-04/S2-05 → S3 → S4 → S5. Provider preparation can occur
alongside S2-01; documentation/corpus preparation can proceed while a runtime
dependency is blocked. Do not interpret this as authorization to spawn agents.

For each item maintain this record in a development update or linked issue:

```text
ID / owner / state:
Problem and acceptance criterion:
Dependency and environment:
Commit / changed files:
Checks actually run / evidence location:
Result / unresolved failures:
Risk or scope change:
Next action:
```

P0: scope bypass, credential disclosure, unsafe execution or evidence corruption.
P1: required flow unusable, incorrect clean result, cancellation/recovery failure
or mandatory gate failure. P2: nonblocking defect with a documented workaround.
P3: polish. Fix P0/P1 before discretionary P2/P3 work. Any reproducible regression
gets a focused regression check; do not create tests that merely mirror code.

## Risks and response

| Risk | Impact | Response / owner |
| --- | --- | --- |
| Unverified feature accumulation | Integration backlog may exceed estimates | Baseline first, stop new features, prioritize failures / developer |
| No usable Linux host | Runtime evidence blocked | Establish authorized Linux environment; keep Windows work to portable tasks / owner + developer |
| Real model/API unavailable | Mandatory AI acceptance blocked | Prepare providers early; expose blocked status, never substitute stubs / owner |
| Static snapshots mistaken for full browser scanning | Misleading user expectations | Prominent capability boundaries and negative controls / developer + reviewer |
| Partial detection/maps mistaken for assurance | False confidence | Curated corpus, explicit skipped coverage and mapping rationale / reviewer |
| Report/SQLite failure or upgrade data loss | Evidence trust damaged | Crash, backup/restore, export consistency and migration work / developer |
| Accepted evidence refers to earlier commit | Release integrity failure | Exact-SHA freeze and mandatory regeneration / release lead |
| 14 October date drives bypasses | Unsafe release | Reforecast after S2; never waive gates to meet date / owner |

## Capacity and schedule

Planning assumption: one primary developer with timely owner/provider access and
a reviewer available at milestone boundaries. Rough effort ranges, not commitments:
S2 3–5 focused developer-days; S3 4–7; S4 3–5; S5 2–4, **12–21 days remaining**,
plus environment waits, owner review and unexpected repair. S1 effort is already
spent and is not included. Re-estimate after the S2 baseline; smaller measured
backlogs can shorten this, newly discovered defects can extend it.

The previous **14 October 2026** target remains aspirational and at risk. These
effort ranges do not promise that date. Order work by risk/dependencies and finish
criteria, not by declaring a spiral complete when a date arrives. The owner and
delivery lead rebaseline at each spiral exit. No background automation is created.

## Release authority and work policy

This PM update is documentation only. It does not run tests, deploy or publish.
When the owner starts Spiral 2, use the developer prompt's validation-based flow;
if the owner continues to prohibit testing, continue permitted implementation
but keep verification and production completion blocked. Do not silently override
an active instruction. Publishing a final release requires the owner's release
authorization as well as the technical gates. Routine authorized fixes do not
require repeated permission; external targets/services need the applicable scope.
