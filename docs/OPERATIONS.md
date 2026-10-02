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

## Prepared static-browser runtime

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
