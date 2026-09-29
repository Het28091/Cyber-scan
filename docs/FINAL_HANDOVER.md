# Final handover — 25 October 2026

Updated 29 September 2026. Owner-requested deadline: **25 October 2026
(Asia/Kolkata)**, replacing 14 October. This is a delivery plan, not a scheduled
background task. Work and feedback are handled in active sessions.

## Baseline and finish line

v1.1.0 is already published. Its recorded acceptance is 104 tests, 94% statement
coverage, all 14 recurring CI jobs, and gated release publication. These are dated
results, not a guarantee of future service availability or zero defects.

The remaining milestone is owner-machine acceptance and final handover.
Freeze new features. Fix reproducible failures in the existing Linux, non-AI
workflow; retain explicit preparation of external scanners and databases.
AI, automated login, role comparison, active exploitation, new dashboard scanner
presets and exhaustive pentest/compliance claims remain outside scope.

## Schedule

| Window | Deliverable | Completion evidence |
| --- | --- | --- |
| 29 September–4 October | Owner installation and workflow feedback; prioritize blockers | Redacted reproduction details, Linux/Python versions |
| 5–14 October | Batch confirmed fixes; update affected instructions | Targeted regressions and reviewed changes |
| 15–20 October | Freeze release candidate; complete owner retest | Checklist below, with failures resolved or explicitly scoped |
| 21–24 October | Final CI, release packaging if code changed, handover review | Passing required gates; matching tag, assets and checksums |
| 25 October | Final handover | Release link, setup/demo instructions, known limitations and backlog |

If no code changes are required, keep the verified v1.1.0 release instead of
manufacturing a new version. If fixes are required, choose the next appropriate
version and update the version-specific publication gate before release.
Never overwrite the existing release/tag.

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

## Final acceptance

- [ ] Owner-machine checklist recorded; reproducible in-scope blockers resolved.
- [ ] Setup, scope/authentication and report instructions reflect actual behavior.
- [ ] Every code fix has appropriate validation; required release gates pass.
- [ ] Published tag and downloaded assets match the release commit/checksums.
- [ ] Final version, limitations and genuinely deferred items are clearly identified.

The checklist is pending owner feedback; publication of v1.1.0 alone does not mark
owner-machine acceptance complete.
