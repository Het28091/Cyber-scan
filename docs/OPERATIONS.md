# Local operator recovery and maintenance

Use a supported Linux x86_64 host and the application's dedicated Python environment.
Keep the dashboard loopback-only. No server-side task described here needs an AI provider.

## Report export recovery

Exports now stage files before replacing reports. `report-publication.json` stays
INCOMPLETE until all replacements and their SHA-256 inventory finish. The dashboard
blocks downloads while incomplete; changed report bytes also fail the download check.
An interrupted multi-file replacement is detected, not an atomic multi-file transaction.
Legacy reports without a publication record remain readable and are labeled legacy.

After resolving disk space, permissions or PDF prerequisites, run:

```bash
bash run.sh export-reports RUN_ID --output runs
```

Use `resume RUN_ID --output runs` only for a stopped, interrupted assessment.
Neither command repeats target/provider requests. Never edit original findings to
make a recovery pass. Keep failed evidence for diagnosis. Hidden `.report-stage-*`
directories left by SIGKILL can be reviewed and removed only after all writers stop;
never delete the whole evidence directory to repair an export.

## Backup, restore and rollback

1. Stop the dashboard normally and wait for all CLI assessments/exports to finish.
2. Record `git rev-parse HEAD`, Python version and dependency lock files alongside
   the backup. Recover stopped RUNNING assessments before proceeding.
3. Choose a new backup directory outside the evidence tree, on storage you control:

   ```bash
   bash run.sh backup --output runs --destination /absolute/backup/new-snapshot
   bash run.sh restore /absolute/backup/new-snapshot --destination /absolute/restored-runs
   bash run.sh dashboard --output /absolute/restored-runs
   ```

The parent destination directory must exist. Backup locks out a live dashboard,
rejects active jobs/CLI records, links, incomplete reports and future database
schemas, checks SQLite integrity and verifies that source bytes stayed unchanged.
Restore checks the complete manifest and writes only to a new directory. It never
merges, overwrites or removes existing evidence. Compare run IDs, findings, review
history, due dates, profiles and a report download before relying on the copy.

This is a **quiescent local snapshot**, not a live database backup. An independently
started CLI writer can race the operation: stop all writers, and do not run them
until it finishes. The snapshot includes private evidence and local paths; protect
the copy like the original. Hashes detect accidental corruption, not malicious
replacement of both content and manifest. Use separately managed encrypted storage
where needed. Bounds are 100,000 files and 10 GiB; larger stores need a reviewed
backup method. Preserve old backups until a restore has actually been checked.

For an upgrade, first take and verify a pre-upgrade snapshot, retain the old
application commit, and test the new application against a restored copy. For
rollback, restore that **pre-upgrade** snapshot into a new directory and use the
matching old application. Do not point an old application at a newer schema or
promise an in-place downgrade. Future database schema versions are refused.

## Diagnostics and capacity

### Prepared wheels and candidate packages

Both direct bundle preparation and release packaging now require a clean Git
source root. Untracked, ignored or modified files inside packaged paths are
rejected before creating a direct bundle; linked inputs are rejected too. Keep
private configuration outside those paths. Do not commit secrets to satisfy this
check. Source is checked again before the manifest is written, which records
the commit. Installed/source-archive copies without Git metadata can still run
scans; prepare new bundles from a clean checkout. This is not protection against
a malicious concurrent writer; stop source edits during packaging.

Use a reviewed local directory of wheels matching `requirements.lock` and the
Linux/Python version to prepare without reaching an index:

```bash
bash run.sh bundle prepare --output /absolute/new-bundle \
  --wheelhouse /absolute/prepared-wheels
PYTHONPATH=. python scripts/package-release.py --commit FULL_SOURCE_COMMIT \
  --output artifacts/new-candidate --channel candidate \
  --wheelhouse /absolute/prepared-wheels
```

`--wheelhouse` is mutually exclusive with connected download preparation
(`--download-dependencies` for bundles, `--with-wheels` for packages). Only
hash-locked binary wheels are resolved; missing, incompatible or altered files
fail, without online fallback. pip configuration/environment source overrides are
disabled during preparation and installation. Preparation and pip installation
have 120-second subprocess limits. A failed output is not a completed bundle;
retain it for diagnosis and retry into a new directory. Supply approved CA/proxy
settings through the normal OS environment when connected preparation is needed.

The Kali test candidate is under
`artifacts/checkpoints/production-oct10/candidate-offline/`, source `1d35d63`.
Its archive checksums, fresh install, actual offline CLI and PDFs passed under
network denial. It is a testing candidate, not a new 1.1.0 stable release.
Check the exact source and matching Python minor before using a candidate.

### Prepared Kali Gitleaks

The checksum-verified 8.24.2 binary is at
`/home/kali/Cyber-scan/artifacts/tools/gitleaks-8.24.2-oct10/bin/gitleaks`.
Set this as the Gitleaks executable in scanner configuration, or add its directory
to PATH in the process launching the application. The preparation does not alter
system packages or the dashboard's existing environment. Actual detection and
isolation passed; source mounts remain read-only and scanner networking is denied.

### Capacity monitoring

Use doctor/preflight before an assessment. Missing tool/model/key, unavailable
sandbox and rejected scope are blockers, never evidence of a clean target. Never
disable isolation to silence an error. API credentials belong in environment
variables, not saved profiles, reports or support tickets. Share redacted diagnostics.

Monitor free disk before large assessments: staged report generation temporarily
needs both old and new reports, and backup needs another full evidence copy. Job
summary retention is 200 terminal records; it does not delete assessment evidence.
The source and upload limits are explicit configuration controls, not throughput
guarantees. `integration/operations_acceptance.py` records reference measurements;
owner hardware and performance budgets still require acceptance.

### Recovery and boundary checks for maintainers

`test_report_publication` now kills a real export subprocess after an artifact has
been replaced, verifies INCOMPLETE blocks downloads, and regenerates the reports.
`test_hardening` submits 20 jobs concurrently while holding the worker at a test
barrier: ten are admitted, rejections leave no extra inputs, and cancellation
releases a slot. This verifies admission control, not queue throughput under load.

`PYTHONPATH=. python integration/storage_acceptance.py` fills an isolated 1 MiB
tmpfs and exercises actual ENOSPC, preserved previous evidence, blocked downloads
and retry after reclaiming space. It requires Bubblewrap with `--size` support;
it never fills the host's evidence volume. The CI runtime builds upstream 0.11.0
from its checksum-pinned [upstream release archive](https://github.com/containers/bubblewrap/releases/tag/v0.11.0). Ubuntu 24.04's hosted runner denied the
required namespace operation, so this exercise uses Ubuntu 22.04 without disabling
host security policy. This is not physical-disk power-loss durability testing.

`PYTHONPATH=. python integration/capacity_acceptance.py` verifies the exact default
source traversal limits and one unit beyond each: 5,000 files, 1,000,000 bytes per
file and 50,000,000 total bytes. Results include traversal timing; they do not
establish full-assessment/reporting latency or an owner-approved operating budget.
All exercises use disposable owned fixtures. See INDEPENDENT_EXECUTION.md for
the source-specific results; implementation presence alone is not acceptance.

## Progress, support and evidence retention

The full source/owned-HTTP/queue exercise is `integration/load_acceptance.py`.
Its measurements are separate from traversal-only boundary checks.

Live progress is updated at each checkpoint. SQLite/partial JSON writes occur on
the first checkpoint and at most once per 250 ms thereafter; terminal success,
failure and handled cancellation persist the latest in-memory evidence. A hard
kill can lose progress since the last completed disk checkpoint. Treat such runs
as interrupted; this does not claim power-loss durability.

For support, record the exact commit, Linux/Python/tool versions, selected mode,
failure category and smallest owned reproducer. Share only reviewed, redacted
preflight/coverage/publication metadata. Do not upload credentials, private source,
provider responses or an entire evidence tree to public issues.

Assessment evidence does not expire automatically. The 200-terminal-job summary
limit does not remove assessment runs. The owner chooses retention and verifies
backup/restore before deliberate disposal. Stop writers before maintenance. Support
contacts, response times and release observation periods require owner decisions.
See OWNER_ACCEPTANCE_INPUTS.md for the concrete remaining prerequisites.

## Prepared static-browser runtime requirements

Static snapshots require a real Chromium executable, Bubblewrap, cgroup v2 and a
working systemd user manager with memory/pids controllers. Check
`systemctl --user show --property=Version` in the same login environment that runs
Secaudit. On Kali the verified executable is `/usr/lib/chromium/chromium`; the
distribution's shell wrapper may require additional host files and is not the
verified executable. Do not substitute `--no-sandbox` or relax host policy when
preparation fails. A system administrator must prepare the supported environment.

Each snapshot uses a unique transient service and kernel-verified 1 GiB memory,
zero swap, 128 tasks, 512 descriptors, 2 TiB virtual-address ceiling and 8 MiB per
internal file. Large virtual reservations are not physical allocation. Writable
mounts are ephemeral; their pages count toward the memory budget. Snapshot output
is separately capped at 1 MB, input at 64 KiB, and the default renderer lifetime
at 15 seconds. The parent stops the unit; a systemd watchdog covers parent death.
Page scripts are disabled before loading the fetched HTML. Browser network is
isolated, so linked images/styles will not load. This is a static inventory, not
interactive browser scanning. Runtime preparation failure means coverage missing.
