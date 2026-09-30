# Manual testing checkpoint — 30 September 2026

The source checkpoint has since been extended into the
[first-round implementation handover](ROUND_ONE_HANDOVER.md). Use current GitHub
`main` for that handover; the earlier ZIP remains the earlier snapshot. Tests and
debugging are still deferred. For optional AI, restart with `--experimental-ai`.
Also try the new job Details/preflight view and Refresh report snapshots action.

Feature development is paused here for owner testing. This is an **unreleased,
unverified source checkpoint**, including the current uncommitted changes.
The most recent feature-first passes have not been tested or debugged. Earlier
test results do not validate them. The application version still displays 1.1.0;
that does not make these changes part of the published v1.1.0 release.

## Start on Linux

The checkpoint is also available from the repository's `main` branch. For a fresh
Linux checkout:

```bash
git clone https://github.com/Het28091/Cyber-scan.git
cd Cyber-scan
```

Then use the setup/scan/dashboard commands below. If you already have a clean
checkout, use `git pull --ff-only origin main` from its `main` branch instead.
The checkpoint commit skips CI because testing was explicitly deferred; it is
not a passing build or a stable release.

Use a Linux machine or Linux VM with Python 3.11–3.14. Native Windows is not
supported. Transfer and extract the checkpoint source ZIP; do not download the
published v1.1.0 archive expecting these new features. Start in the extracted
folder containing `setup.sh` and `run.sh`.

```bash
bash setup.sh
bash run.sh scan --config config/offline.json --output runs
bash run.sh dashboard --output runs
```

Initial setup needs internet for missing dependencies and may request sudo for
OS prerequisites on Debian/Ubuntu. It does not install AI models. The offline
demo scan uses synthetic source in `demo/source`; it does not execute that source.
The first scan should print a run ID and save evidence under `runs/<run-id>/`.
A successful assessment still says `COMPLETED_WITH_LIMITATIONS`.

Open **http://127.0.0.1:8765** on that same machine. Sign in as `operator`, using
the session password printed in the dashboard terminal. Keep the terminal open;
Ctrl+C stops the dashboard. The password changes when it restarts. For a remote
Linux host, use your existing SSH access with local port forwarding; the dashboard
is intentionally bound to loopback.

## First manual pass

Record PASS, FAIL or NOT TESTED against each item. These are expected behaviors,
not claims that this checkpoint has passed them.

1. **Baseline run:** the offline demo appears in the dashboard. Open its findings
   and coverage; candidate findings and limitations are visible.
2. **New assessment:** choose source `demo/source`, leave target blank, choose
   **Strict offline · No AI**, leave additional scanners off, accept authorization,
   and start. Observe the job reach a terminal state and open its evidence.
3. **Profiles:** configure the same source-only assessment. Enter a profile name,
   review the configuration, and save as new. Reload the list, load the profile,
   and confirm the advanced editor contains its settings and consent is cleared.
   Update it or save a copy. No scan should start from saving/loading alone.
4. **Operator review:** open a finding, set `REMEDIATION_PENDING`, a rationale,
   an owner and a due date. Save, close and reopen it; the decision and revision
   should remain. Use synthetic notes, not passwords or sensitive evidence.
5. **Remediation:** open **Reports & evidence** for that assessment. Filter the
   work list by owner/status. A past UTC due date should be overdue for an open
   action. Download the current JSON and CSV plan and inspect those files.
6. **Reports:** open/download technical HTML, PDF, JSON findings and coverage.
   Existing report files are snapshots; they do not automatically include later
   operator edits. The current review/action-plan downloads do include them.
7. **Retest comparison:** perform another scan with the same source/settings,
   then compare it with the earlier run from Reports & evidence. Unchanged
   findings should remain observed, not become resolved automatically.
8. **Persistence:** stop/restart the dashboard with the same `--output runs`.
   Runs, reviews and profiles should persist. Log in with the new session password.

To regenerate report snapshots with current reviews, stop the dashboard after
jobs finish and run (replace `RUN_ID` with the full saved run ID):

```bash
bash run.sh resume RUN_ID --output runs
bash run.sh remediation RUN_ID --output runs > remediation-plan.json
bash run.sh remediation RUN_ID --output runs --format csv > remediation-plan.csv
```

## Optional later checks

- Internet/no-AI mode sends package identifiers to OSV; choose it explicitly.
- For new OpenAPI/Kubernetes rules, scan your owned JSON manifests with the
  normal `openapi`/`config` modules; see [DECLARATION_CHECKS.md](DECLARATION_CHECKS.md).
  Kubernetes YAML and rendered Helm projects are not covered by these rules.
- AI requires a prepared provider/model, configuration, pinned IPs and server
  environment references. Start with `SECAUDIT_EXPERIMENTAL_AI=1 bash run.sh
  dashboard --output runs` only when prepared; see
  [EXPANDED_IMPLEMENTATION.md](EXPANDED_IMPLEMENTATION.md).
- Session/role/browser workflows need explicit bounded scope and dedicated test
  accounts. Real Chromium/Bubblewrap and external scanners need separately
  prepared Linux tools. Their absence is NOT TESTED, not a clean assessment.

## What to send back

Send the checkpoint archive name, Linux distribution, Python version, failing
step/command, expected behavior and exact redacted error. If setup fails, include
the terminal error; if a scan fails, include its job diagnostic and relevant saved
preflight/run events. Do not share session passwords, API keys or private source.

No final release, real-provider acceptance, comprehensive detection claim or
original-brief sign-off is included in this checkpoint. Pending failures should
be addressed in the next improvement pass after owner feedback.
