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
  `spiral2-local-tests.log` (untracked diagnostic, not release evidence).

Owner reports a Kali VM running the project and Ollama on the host PC. S2-04
remains BLOCKED until the owner supplies VM access/project path, reachable provider
endpoint, exact model and permission for synthetic-fixture metadata disclosure.
No provider calls have occurred; an actual compatible API provider is still needed.

Open P1: required Linux suite/distribution gate failures, diagnosis in progress.
No P0 defect has been established by the checks so far; this is not a security
clearance. All S2 tasks remain unaccepted; next action is Linux regression diagnosis.
