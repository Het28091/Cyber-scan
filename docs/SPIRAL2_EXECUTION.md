# Spiral 2 execution record

Started 30 September 2026 at owner request; testing/debugging are now authorized.
Starting commit: `7bfa540354743b601f6a42676fa12c00ed18b764`; working tree was clean.

## S2-01 baseline

- Local host: Windows; WSL reports not installed; Docker/Podman are unavailable.
  No Linux isolation was bypassed or emulated to claim runtime acceptance.
- GitHub CLI workflow dispatch failed because CLI authentication is absent.
  Public GitHub Actions results are readable without credentials. A normal push
  of this baseline record will trigger the existing Linux verification workflow.
- Portable checks: Ruff E9/F821/F822/F823 passed, JavaScript syntax passed, and
  38 selected tests ran: 37 passed, one Linux pipeline test skipped.
  Commands: `python -m ruff check --select E9,F821,F822,F823 secaudit scripts tests`,
  `node --check secaudit/static/app.js`, and
  `python -m unittest test_expanded test_review_workflow test_release_gate -v`
  with repository/tests/local tool paths on PYTHONPATH.
- Real local/API provider configuration has been requested using host/model and
  environment-variable names only. No provider calls have been made.

Spiral 2 is IN_PROGRESS, not accepted. Supported Linux and real-provider evidence
remain pending. This baseline commit intentionally does not skip CI.

## S2-02 / S2-03 / S2-05 repair checkpoint — 1 October 2026

Linux baseline source: `2835ec67c3b02001fa3ea0ef3e0f54221e5e4a00`.
[Actions run 36746995096](https://github.com/Het28091/Cyber-scan/actions/runs/36746995096)
passed live OSV/Gitleaks, Semgrep and both inventory adapter jobs. The main tests
and all eight distribution jobs failed (the latter in the combined setup/test
step). Root causes are not yet established. Public log download returned HTTP 403;
CI annotations are being added for exact regression failure tracebacks. Existing
checks and coverage thresholds remain mandatory. Browser result is pending review.

Repair checkpoint changes (exact source is the commit containing this section):
- S2-02: profiles now resolve the selected preset's actual default source modules
  and save that explicit selection. Previously preview/stored defaults could
  disagree with actual execution. The regression failed before the repair.
- S2-03/S2-05: browser acceptance selects the JSON editor before editing a hidden
  advanced scope field. New regressions cover profile persistence/stale revisions,
  malformed configuration, module disclosure, no-DNS preview, report evidence
  preservation, review dates and queue/restart diagnostics.
- Windows targeted `python -m unittest test_spiral2 -v`: 6 PASS, 2 Linux-only
  SKIP; Ruff correctness and `git diff --check`: PASS. This is not Linux acceptance.
- Diagnostic full Windows discovery: 95 tests, 6 failures, 11 errors, 3 skips.
  Failures include unavailable fcntl/resource/fchmod/sysconf/seccomp/bash and their
  dependent runtime paths. No platform boundary was disabled. Raw local output:
  `artifacts/checkpoints/spiral2/windows-discovery.log` (local ignored diagnostic,
  not release evidence).

Owner reports a Kali VM running the project and Ollama on the host PC. S2-04
remains BLOCKED until the owner supplies VM access/project path, reachable provider
endpoint, exact model and permission for synthetic-fixture metadata disclosure.
No provider calls have occurred; an actual compatible API provider is still needed.

At that checkpoint, open P1: required Linux suite/distribution gate failures,
diagnosis in progress.
No P0 defect has been established by the checks so far; this is not a security
clearance. All S2 tasks remain unaccepted; next action is Linux regression diagnosis.

## Linux repair findings — 1 October 2026

- `13e0a68a5074843e3badf121503cf7d0f0a5d030`: repaired the stale assertion
  expecting "disabled" instead of the explicit experimental opt-in error. The
  test now additionally asserts that transport is never invoked. This resolved
  the main suite and all eight setup/distribution failures; they were not setup
  implementation defects. Workflow steps remain enabled, with coverage >=81%.
- Chromium exposed exact-label selector failures on dynamic selects. Use their
  accessible combobox roles. The JSON editor must be selected before filling its
  hidden scope field. These are test repairs for intentional prototype UI changes.
- Browser async polling initially inspected a report while its refresh was still
  RUNNING. Explicit awaited fetch/predicate polling fixed this harness race.
  Direct export and strengthened real queue regressions confirmed saved review
  inclusion. The suspicion of missing reviews was not a demonstrated product bug.
- `4403ca2249d8cd4e64fb7d30bc12a6e74e8c3db9`,
  [run 36807462335](https://github.com/Het28091/Cyber-scan/actions/runs/36807462335):
  all mandatory CI jobs passed, including actual Chromium and all eight Linux
  setup/distribution combinations. Deployment-specific authorized-target job was
  SKIPPED by its explicit marker condition and is not claimed as acceptance.
- `e6eb821c882c858c94ea1f9cc846a97bcb489f8d` extended actual server restart,
  persisted profile/review and incomparable-context UI comparison coverage.
  These flows reached the final audit, which found one serious keyboard-access
  violation in scrollable comparison output. Fixed with focusability and a named
  region; the new browser assertion tabs into it. Final rerun is pending below.
- One live OSV/Gitleaks job failed at `43f9bba`; detailed logs were unavailable.
  The cause remains unclassified. Subsequent runs passed unchanged live logic.
  This is recorded as intermittent external acceptance uncertainty, not proof
  that a service or the product caused that individual failure.
- Combined portable checkpoint: `python -m unittest test_expanded
  test_review_workflow test_release_gate test_spiral2 -q`: 46 tests, 43 PASS,
  3 Linux-only SKIP. JavaScript syntax and diff whitespace checks passed.

Provider blocker owner: project owner. Next inputs: Kali SSH/access method and
project path; exact host Ollama endpoint/model and fixture disclosure approval;
actual compatible HTTPS API/model, credential environment-variable name and
approved pins/budget. Never provide credentials in chat. The developer will run
`integration/ai_acceptance.py` against reviewed configurations on Linux and record
real provider evidence separately from the protocol fixtures. The loopback tunnel
preparation is in [AI_QUICKSTART.md](AI_QUICKSTART.md).

No real provider call, model download, release tag or publication occurred.

## Verified Linux checkpoint and stopping condition

Source: **`6eda00ad94f796fe1229d22e967e6869e08bf37c`**.
[Actions run 36807699088](https://github.com/Het28091/Cyber-scan/actions/runs/36807699088)
completed SUCCESS. [Saved job/step evidence](evidence/spiral2-linux-checkpoint.json)
records all 14 mandatory jobs PASS: main unit/integration/correctness/security/
dependency/coverage gates; eight Ubuntu 22.04/24.04 × Python 3.11–3.14 setup,
repeated offline setup, offline-install and candidate packaging jobs; actual
Chromium lifecycle/accessibility acceptance; live OSV/Gitleaks; Semgrep; Syft;
Trivy. No check was disabled to obtain this result. The additional marker-gated
authorized-target deployment job remains SKIPPED and is not claimed as verified.
Browser screenshots, accessibility output and result.json are retained in the
run's `dashboard-browser-evidence` artifact (14-day CI retention); local download
requires GitHub authentication. The durable JSON here preserves job/step outcomes,
not those artifact contents or full logs.

| Task | Implementation | Verification / remaining acceptance |
| --- | --- | --- |
| S2-01 | Baseline established | VERIFIED on GitHub Linux runners; owner Kali not yet accessed |
| S2-02 | Profile preset/module fix complete | VERIFIED through focused regressions, full suite and browser source/ZIP journeys; internet/non-AI regressions and live OSV pass |
| S2-03 | Keyboard comparison fix complete | VERIFIED real Chromium: profile save/load, fresh consent, ZIP failure/recovery, saved review owner/due date, report refresh, downloads, failure diagnostics, cancellation, process restart, persistence, incomparable-context comparison and accessibility |
| S2-04 | Existing adapter code retained | BLOCKED: protocol fixtures and failure/budget regressions PASS, actual Ollama/API not tested |
| S2-05 | Stale assertions/selectors/async waits repaired | VERIFIED full Linux suite and existing >=81% coverage gate; strengthened no-transport and queue-report assertions |

No known open P0/P1 functional defect remains from this checkpoint's executed
checks. This does not certify security, universal scanner detection, owner-machine
compatibility or operational recovery; Spirals 3–5 remain planned. Residual risk:
one earlier live-adapter failure was unclassified, despite subsequent passes.

**Milestone: BLOCKED / NOT ACCEPTED.** Further real-provider work requires the
owner inputs listed above. Next: S2-04, then owner demonstration and recorded
milestone decision. No autonomous move to Spiral 3 or production. Subsequent
documentation commits cite this tested source explicitly; they are not new
exact-commit release acceptance records.
