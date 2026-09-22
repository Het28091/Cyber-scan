# Progress — 0.4.0

Updated 2026-09-22. Project direction: Linux-only, non-AI scanning with optional
internet access. Scope is recorded in [SCOPE.md](SCOPE.md).

## Completed in this release

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

## Verified here

- 51 automated tests passed on Linux, including a complete internet-mode pipeline
  using a controlled advisory response and an assertion that AI never runs.
- A live local-web assessment in internet mode completed: 2 assets, 6 candidate
  findings, no AI requests.
- Linux repeat setup with `--offline` passed.
- Dashboard JavaScript syntax passed; existing HTTP authentication/CSRF/job tests passed.
- A real internet-mode source assessment completed with five synthetic source findings.
  The OSV lookup was blocked by the host's DNS/public-address policy and correctly
  appeared NOT TESTED; no successful live OSV integration is claimed.

## Remaining acceptance work

- [ ] Successful OSV lookup on an unrestricted Linux machine.
- [ ] Actual externally hosted authorized target test; local fixtures cover client behavior.
- [ ] Browser-level UI verification; Chromium installation was unavailable in this environment.
- [ ] End-to-end verification of optional scanner binaries on a host allowing Bubblewrap.

## Next milestone

Prioritize live Linux acceptance and broader deterministic checks before adding AI.
Browser scanning and authenticated role testing require their own tested scope and
network controls. No percentage-complete estimate is used to hide unverified work.
