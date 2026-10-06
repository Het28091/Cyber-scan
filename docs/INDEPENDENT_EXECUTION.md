# Provider-independent execution

## Load and mapping checkpoint — 6 October 2026

Source `c1cf5989d5561b19df4486b2b3d31da18274900a`. The operations acceptance
job passed its full source, owned HTTP and actual queue exercises on Ubuntu 22.04,
Python 3.12.14. Results: 4,999-file full assessment 1.165 s / 4,999 assets /
1,013,017 report bytes; twenty HTTP GETs plus one preflight HEAD in 2.274 s;
ten queued source jobs all COMPLETED in 2.814 s. Maximum child RSS across the
exercise was 38,696 KiB. These are synthetic CI observations, not approved owner
hardware budgets or general throughput guarantees.

S4-01/05 repair: the earlier full scan at `dbd87af` timed out after 60.443 s with
2,014 assets. Per-file rewrites of growing SQLite/JSON checkpoints caused excessive
work. The repaired path keeps live evidence current while limiting disk checkpoints
to one per 250 ms after the first; terminal paths always persist current evidence.
The 60-second timeout, input limits and sandbox boundaries remain unchanged.
Regression coverage verifies terminal failure preserves work since the last disk
checkpoint. A hard kill can lose progress since the last completed disk checkpoint;
this is documented, not a power-loss durability guarantee.

S3-04 repair/review: deduplication no longer mutates scanner findings or accumulates
duplicate provenance across checkpoints. Regression tests cover repeatability,
input isolation, role/location/description identity and presentation-field stability.
[DETECTION_REVIEW.md](DETECTION_REVIEW.md) reconciles all 28 fixed built-in rule IDs:
five have specific curated mappings; others have only generic NIST identification
associations. Dynamic upstream rules are separate. Primary sources were reviewed
on 2 October; no compliance certification or independent review is claimed.

The HTTP load fixture initially failed because its `headers` method collided with
BaseHTTPRequestHandler's request-header attribute. Renaming the fixture method
restored actual HTTP execution; no application safety boundary changed.

Current CI: [run 37491440348](https://github.com/Het28091/Cyber-scan/actions/runs/37491440348).
All **16 mandatory jobs PASS**. The optional deployment-specific authorized-target
job was skipped and is not counted as a pass. Completed-run metadata and actual
load measurements are saved in [durable evidence](evidence/load-mapping-linux-ci.json).
No new Kali result is claimed.

Next required inputs: [OWNER_ACCEPTANCE_INPUTS.md](OWNER_ACCEPTANCE_INPUTS.md).
The remaining milestone work requires configured local/API providers, owner-machine
demo and workload approval, plus independent review. These are not waived by CI.
S2 remains blocked; S3/S4 are not accepted; S5 freeze/publication has not started.
No release was created and no final gate was marked PASS by this checkpoint.

## Earlier checkpoints

Owner authorized continuation on 1 October 2026 while S2-04 remains BLOCKED.
Starting source: `25be9e0` (Spiral 2 evidence checkpoint). Initial working tree clean.
Windows editing/portable tests; GitHub Linux runners for runtime acceptance.

Active packages: S3-01/02 security boundary review; S3-03 real isolated static
Chromium fixture; S3-04 bounded detection corpus; S3-05 dependency/isolation gates;
S4-02 interrupted-report detection; S4-03 backup/restore exercises; S4-04 runbooks.
S4-01 can measure CI reference workloads, but owner-approved operating budgets
and owner hardware acceptance remain external inputs. S5 release preparation
can be documented; freeze, final exact-commit acceptance and publication cannot
be completed before the predecessor gates and owner release authorization.

No task below is verified merely because code or instructions were added.

## Verified implementation checkpoint — 2 October 2026

Source: `250e82e5b073e94ead33c7fd2dd76a440f40cc68`. Owner-authorized Kali
checkout: `/home/kali/Cyber-scan`, Linux x86_64 kernel 6.19.14+kali-amd64,
Python 3.13.12, Chromium 148.0.7778.178, Bubblewrap 0.11.2, user systemd 260.1-1,
cgroup v2. The initial offline setup passed at `6458dff`; that setup result is
historical, while the checks below ran against the checkpoint source.

| Task | Implemented / executed | Verification and remaining scope |
| --- | --- | --- |
| S3-01/02/05 | Developer threat review and existing isolation, scope, credentials, redaction and dependency controls | Current unit and mandatory security/live jobs PASS; independent review and real provider evidence still required |
| S3-03 | Real static Chromium snapshot using CDP pipe, scripts disabled before navigation, verified cgroup containment | Kali and CI PASS: one pinned fetch, static form/password/link detected, no script-generated form or subresource request, oversized allocation terminated; deployment-specific session acceptance remains separate |
| S3-04 | Declared built-in source/config/OpenAPI/Kubernetes corpus | 21 TP, 0 FP, 0 FN; 11 clean cases PASS. Separate external adapter jobs PASS. Full mapping/fingerprint reconciliation and representative owner dataset remain open |
| S4-01 | Reference Linux workload measurements | 10/100/1000 synthetic files: 0.303/0.511/9.074 seconds; reports 113654/130488/301492 bytes. Peak child RSS 38160 KiB. Near-limit/target/queue measurements and owner-approved budgets remain open |
| S4-02 | Staged report publication, INCOMPLETE/READY manifest and read-time digests | Injected failure, tampering, interrupted publication and retry regressions PASS; broader process-kill/full-volume exercises remain open; no power-loss atomicity claim |
| S4-03 | Quiescent backup/restore, schema guards, upgrade and pre-upgrade-copy rollback | Real old release `55ac666b57963fe0e45910ec51a31179ad566be0` to current exercise PASS; restored bytes/reviews/profiles and unchanged findings checked. Not a live backup or in-place downgrade |
| S4-04/05 | Recovery runbook, explicit renderer resource verification, focused regression coverage and mandatory operations/browser publication checks | Implemented and checked within the declared exercises; support/retention policy and owner operational acceptance remain open |

Commands actually executed on Kali:

```bash
.venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=.:tests .venv/bin/python -m unittest test_browser_resource test_browser_snapshot -v
PYTHONPATH=. .venv/bin/python integration/target_browser_acceptance.py --executable /usr/lib/chromium/chromium --evidence artifacts/checkpoints/independent/target-browser.json
PYTHONPATH=. .venv/bin/python integration/quality_corpus.py --help
PYTHONPATH=. .venv/bin/python integration/operations_acceptance.py --help
```

The last two scripts do not parse command-line arguments: `--help` was ignored
and their complete exercises ran. Use the commands without that argument when
repeating them. Full suite: **162 tests PASS, no skips, 10.193 seconds**.

Durable copied evidence: [test log](evidence/tests-current.log),
[renderer](evidence/target-browser.json), [operations](evidence/operations.json),
[corpus](evidence/detection-quality.json). These files correspond to the source
above; they contain owned fixture results, not user assessments.

[CI run 37039191586](https://github.com/Het28091/Cyber-scan/actions/runs/37039191586)
passed **all 16 mandatory jobs** at this source, including eight Ubuntu/Python
distribution combinations, real dashboard browser, target browser, operations,
live scanners and the main correctness/security/test job.
[Persisted CI metadata](evidence/independent-linux-ci.json) records steps and results.
The optional deployment-specific authorized-target job was skipped and is not
counted as a pass. No release records were marked PASS and no release was published.

### Renderer defect resolution

Kali diagnostics identified three startup incompatibilities: virtual-address
reservation, descriptor usage and a 2 MiB shared-memory file exceeding the old
1 MB output-derived file cap. Rendering now uses a dedicated user systemd service
with kernel-verified 1 GiB memory, zero swap and 128-task limits; finite 2 TiB
virtual address, 512-descriptor and 8 MiB internal-file limits; and a runtime
watchdog. Internal writable mounts are ephemeral and their allocated pages count
toward the cgroup memory budget. Returned output remains capped at 1 MB. CDP DOM
retrieval replaces script-dependent dump-dom. Bubblewrap and Chromium's own
sandbox stay enabled; missing containment fails closed. No host isolation policy
was disabled. The previously open renderer P1 is resolved in the tested environments.

### Remaining decisions and next work

S2-04 remains BLOCKED: owner must prepare endpoint/model and disclosure for local
Ollama and a compatible API, with credentials provided through environment setup.
No provider credential is configured in the tested SSH environment; no arbitrary
shared key or paid inference was used. Developer then runs real provider acceptance.
Owner UAT, representative dataset/budget approval, independent review and final
exact-commit gates remain outstanding. S3/S4 are IN_PROGRESS, not accepted.
The next checkpoint below advances the recovery and input-boundary work; whole
assessment/queue throughput and mapping/fingerprint reconciliation remain open.

## Recovery and limits checkpoint — 2 October 2026

Source: `f02e1e07657b1dd78a01fc69b76d2132f8d0e9ee`.
Owner explicitly authorized continuing without the VM after SSH became unavailable.
[CI run 37043137223](https://github.com/Het28091/Cyber-scan/actions/runs/37043137223)
passed **all 16 mandatory jobs**; the optional deployment-specific target job was
skipped. [Persisted metadata](evidence/recovery-linux-ci.json) includes job/step
outcomes and artifact identities/digests. `operational-evidence` contains storage,
capacity and upgrade/restore results with the workflow's 14-day retention. Raw
artifacts were not downloaded through the unauthenticated API; no timings are
invented here. Earlier copied measurements above remain tied to their earlier SHA.

| Task | Executed check | Outcome / limit |
| --- | --- | --- |
| S4-02 | Real export child killed after replacing a report artifact; read/download refused until regeneration | PASS in regression suite. Original findings remain unchanged. Test barrier controls kill timing; no simulated process exit |
| S4-02 | Actual ENOSPC on a disposable 1 MiB tmpfs | PASS in operations CI. Prior evidence bytes preserved, incomplete download rejected, space reclaimed and retry succeeds. No host volume filled; no power-loss durability claim |
| S4-01 | 20 concurrent submissions with worker held at a synchronization barrier | PASS in regression suite. Ten accepted, ten rejected, no rejected input files, cancelled slot reusable, terminal inputs cleaned. Admission/cancellation verification, not throughput |
| S4-01 | Default traversal count and bytes, exact bound and one beyond | PASS in operations CI: 5,000 files, 1,000,000 per-file bytes, 50,000,000 total bytes. Exact bound accepted; exceeding it rejected. Whole-assessment/reporting throughput remains open |
| S4-04/05 | Repeatable fixture commands, pinned tool preparation and runbook | Implemented and exercised in mandatory operations job. Release documentation now names all sixteen mandatory jobs |

Commands: `python -m unittest discover -s tests -v` (main CI regression job uses
its existing coverage wrapper); `PYTHONPATH=. python integration/storage_acceptance.py`;
`PYTHONPATH=. python integration/capacity_acceptance.py`; and the existing
`integration/operations_acceptance.py`. All used owned fixtures without AI calls.
The operations job uses Ubuntu 22.04/Python 3.12 and checksum-pinned upstream
Bubblewrap 0.11.0. The other supported distribution combinations remain in CI.

Environment failures retained: Ubuntu 24.04's hosted namespace policy rejected
Bubblewrap with `Failed RTM_NEWADDR: Operation not permitted`; Ubuntu 22.04's old
package rejected `--size`. The fixture now builds the pinned upstream release and
uses the namespace-capable runner. No security policy was disabled. The supported
Python runtime and its library directory are mounted read-only in their original
layout. Fixtures remain bounded and fail closed when preparation is missing.

Before the VM became unavailable, targeted recovery tests and the real storage
fixture passed on Kali at `d3bc7db`. The subsequent full-suite outcome could not be
recovered, so it is **NOT VERIFIED on Kali for this checkpoint**. Kali remains at
that earlier checkout unless the owner updates it; this continuation did not claim
to synchronize an unreachable VM. Current verification is Linux CI, as authorized.

Next: full-assessment and target/queue load measurements, mapping/fingerprint
reconciliation and independent review. Provider configuration, owner operating
budgets/UAT and all final exact-commit release gates remain outstanding. No whole
spiral was accepted and no release was published by this checkpoint.
