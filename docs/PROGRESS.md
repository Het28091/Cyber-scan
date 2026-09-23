# Progress — 0.6.0

Updated 2026-09-23. Project direction: Linux-only, non-AI scanning with optional
internet access. Scope is recorded in [SCOPE.md](SCOPE.md).

## Completed in 0.6.0

- [x] Real OSV query and real sandboxed Gitleaks execution on Linux CI.
- [x] Sandbox network/input/environment/capability boundary acceptance.
- [x] Static scoped authentication, rejected-login handling and secret scrubbing.
- [x] 100 passing tests and 93% subprocess-inclusive statement coverage.
- [x] Fixed the real Gitleaks address-space and stdout-report incompatibilities.
- [x] Persisted [acceptance evidence](evidence/v0.6-live.json).

Current acceptance and remaining v1.0 work: [V06_ACCEPTANCE.md](V06_ACCEPTANCE.md).

## Completed review response in 0.5.0

- [x] Quantified requirements/npm inventory and strict failure on observed dependency gaps.
- [x] Validated DNS caching, bounded terminal job retention and safe failure diagnostics.
- [x] Experimental AI gate and stronger finding identity.
- [x] CI security/dependency gates and coverage reporting configured.
- [x] 87 local regression tests passed; JavaScript syntax checked.
- [x] Review decisions, scope and deferred work recorded in [REVIEW_RESPONSE.md](REVIEW_RESPONSE.md).
- [x] Required OSV/Gitleaks live gate completed; broader follow-ups: [issue 1](https://github.com/Het28091/Cyber-scan/issues/1).
- [x] Static authentication/dashboard acceptance completed; broader follow-ups: [issue 2](https://github.com/Het28091/Cyber-scan/issues/2).

## Completed hardening pass in 0.4.1

- [x] Adversarial source review and 26 additional regression tests.
- [x] Hardened URL/scope parsing, dashboard HTTP handling and connection limits.
- [x] Fixed failed-upload cleanup, competing dashboard ownership and targeted recovery.
- [x] Preserved evidence across later failures; required dataset failures now fail the scan.
- [x] Validated snapshot publication and checked documentation links/commands.
- [x] Recorded residual risks in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).

## Completed in 0.4.0

- [x] Removed Windows launchers, WSL path handling, Windows documentation and Windows CI.
- [x] Kept automatic Linux venv/setup and hash-locked PDF dependencies.
- [x] Added explicit internet/no-AI mode and separate strict-offline policy.
- [x] Blocked AI activation in both first-milestone modes.
- [x] Added reviewed-scope creation with authorization reference and current DNS pins.
- [x] Added fixed-endpoint OSV queries with package-only disclosure and bounded execution.
- [x] Exposed provider failure, incomplete pagination and budget limits in reports.
- [x] Updated dashboard mode selection and network disclosure.
- [x] Added policy, provider, scope and pipeline regression tests.
- [x] Updated GitHub README, scope, progress and verification records.

## Historical verification through 0.4.1

- 77 automated tests passed on Linux, including a complete internet-mode pipeline
  using a controlled advisory response and an assertion that AI never runs.
- A live local-web assessment in internet mode completed: 2 assets, 6 candidate
  findings, no AI requests.
- Linux repeat setup with `--offline` passed.
- Dashboard JavaScript syntax passed; existing HTTP authentication/CSRF/job tests passed.
- A real internet-mode source assessment completed with five synthetic source findings.
  The OSV lookup was blocked by the host's DNS/public-address policy and correctly
  appeared NOT TESTED; no successful live OSV integration is claimed.

## Remaining acceptance work

- [x] Successful real OSV lookup on Linux CI.
- [ ] Actual externally hosted authorized target test; local fixtures cover client behavior.
- [x] Real Chromium UI verification on Linux CI; screenshots reviewed.
- [x] End-to-end Gitleaks verification on Linux CI with mandatory Bubblewrap.
- [ ] Other optional scanner binaries remain unverified end to end.
- [x] Supported Linux/Python installation matrix and offline bundle acceptance.
- [ ] Final versioned release packaging/publication.

## Next milestone

Use the [v1.0 release checklist](V1_RELEASE_CHECKLIST.md) for current completion gates.

Prioritize browser, distribution and release acceptance before v1.0; new features stay frozen.
Browser scanning and authenticated role testing require their own tested scope and
network controls. No percentage-complete estimate is used to hide unverified work.

## v1.0 acceptance in progress — 2026-09-23

New features remain frozen. Added blocking CI acceptance for:

- Real Chromium: keyboard dialogs, malformed-upload recovery, an owned ZIP source
  assessment, finding search/detail, all views, report download and mobile overflow.
- Ubuntu 22.04/24.04 × Python 3.11–3.14: clean setup, repeat offline setup and tests.
- Locked-wheel bundle installation with inherited seccomp network denial, scanning
  from another working directory, paths containing spaces and PDF/SBOM exports.

All gates passed on [run 35815308853](https://github.com/Het28091/Cyber-scan/actions/runs/35815308853).
Browser cancellation and worker-failure diagnostics also passed. Download testing exposed
and fixed JSON serialization and underscore-filename routing bugs. Durable results are
in [acceptance evidence](evidence/v1-acceptance.json); screenshots are retained for 14 days.
At that checkpoint, accessibility review, externally hosted target acceptance and
release preparation remained open; see the newer acceptance entry below. Other optional scanners remain experimental until
verified; their presence is not evidence of end-to-end support.


## Accessibility and candidate packaging — 2026-09-23

- [x] Improved supporting text sizes, focus visibility and contrast; responsive wrapping.
- [x] Zero axe violations across eight browser states; bounded manual review documented
  in [ACCESSIBILITY.md](ACCESSIBILITY.md), with limitations preserved.
- [x] Eight downloadable CI candidate archives with source commit, locked wheels and checksums.
- [x] Downloaded one generated candidate and verified archive and bundle checksums.
- [x] All eleven jobs passed in [run 35816620962](https://github.com/Het28091/Cyber-scan/actions/runs/35816620962).
- [ ] Externally hosted authorized target acceptance: awaiting owner-provided URL and scope.
- [ ] Final stable version, release notes and GitHub tag/release after acceptance.

Candidates remain version 0.6.0 with an explicit candidate channel. No stable v1.0 or
publisher-signature claim is made. CI artifact retention is 14 days.
