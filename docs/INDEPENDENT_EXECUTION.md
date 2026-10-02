# Provider-independent execution

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
Next independent work: process-termination/full-storage recovery exercises and
near-limit/queue measurements, followed by mapping and fingerprint reconciliation.
