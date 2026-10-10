# Owner-selected modes — 6 October 2026

## Production preparation — 10 October 2026

Kali is reachable at the owner's new address. Gitleaks 8.24.2 is now prepared
and passes actual positive/clean and isolation controls; earlier missing-tool
entries below are historical. At `1d35d63`, 181 Kali tests and full CI PASS;
the actual candidate rebuild, install, offline scan and PDFs pass under network
denial. Local-wheel packaging now preserves hash checks without an online fallback.
See PRODUCTION_CHECKLIST.md, OPERATIONS.md and the source-specific VERIFICATION.md
record. Online API acceptance still requires private free-only preparation;
authenticated DVWA and owner/independent acceptance remain open. The prior DVWA
HTTPS certificate and IP scope describe the old address and must not be reused
unchanged for the new address.

## Separate mode improvements — 9 October 2026

Implementation `18fc648`: **177 Kali tests PASS in 9.975 seconds**, with CI run
37963739961 successful. Six actual CLI journeys at `15ca6e4` PASS; copied
[evidence](evidence/three-mode-quality-oct9.json). Tests are separately identified
by mode and provider simulation is explicitly distinguished from live acceptance.

| Mode | Implemented improvement | Current verification | Remaining |
| --- | --- | --- | --- |
| Offline local, no AI/network | Dockerfile check follows the final USER and final stage, including named-stage inheritance; root reset and unknown variable users no longer look safe | Ten Dockerfile cases; two CLI/PDF journeys under inherited seccomp network denial | External base-image users, build arguments, numeric-stage references and nonstandard escape directives are not resolved; representative owner corpus still needed |
| Web-only, no AI | Empty CSP, nosniff and HSTS headers no longer suppress missing-policy findings; evidence distinguishes empty from absent | Empty/nonempty HTTPS fixtures; two real owned HTTP CLI/PDF journeys; exact HEAD/GET counts and AI disabled | Header presence is not full policy validation; authenticated DVWA and active vulnerability detection remain outside these results |
| Online API AI | Reject truncated/filtered/tool/refusal completions even when their JSON looks valid; preserve scanner findings on required-provider failure | Two actual CLI/PDF journeys with simulated compatible-provider responses: accepted stop and rejected length; metadata-only disclosure checked | Real inference needs privately prepared replacement key and a confirmed free-only environment; no paid calls made |

Original curated corpus rerun at `15ca6e4`: 21 TP, 0 FP, 0 FN and 11 clean
cases pass. These counts describe that corpus only, not general vulnerability
accuracy. New mode regression cases are additional checks, not silently added to
that denominator. Unit cases are in `tests/test_mode_quality.py`; run Linux mode
journeys with `python -m integration.three_mode_quality`. CI now runs this harness
in operations acceptance and retains its summary. Temporary fixture reports are
validated then removed; VM logs remain in `artifacts/checkpoints/mode-quality/`.

Kali is reachable at the latest owner-provided address and DVWA has been exercised
as recorded in DVWA_ASSESSMENT.md. Old connectivity/key observations below are
historical. No new real-provider readiness assertion is made in this pass.
Production and whole-spiral acceptance remain open.

External scanner follow-up: Kali's separate live OSV check succeeded, but Gitleaks
is missing on that VM. This is an optional external-module prerequisite, not a
failure of the verified built-in offline/web modes. CI's live OSV/Gitleaks job
passed at `e7480e6` after a prior run failed without detailed diagnostics; see
VERIFICATION.md. Prepare the pinned scanner before claiming VM adapter acceptance.

## Kali checkpoint

SSH restored at the owner's updated address. The clean checkout was fast-forwarded
to `3d72b5b3a9050921c20a29df7e39c7b07e2060b8`; Python 3.13.12 on Kali Linux.
`python -m unittest discover -s tests -v`: **168 tests PASS, 10.867 seconds**.
`integration/load_acceptance.py`: PASS; 4,999-file scan 1.162 s, twenty owned HTTP
pages 2.706 s, ten real queue jobs 3.601 s. Logs remain in the VM's
`artifacts/checkpoints/three-mode/`; timings are synthetic observations.

Two additional owned fixtures passed at that exact source:

- [Offline evidence](evidence/kali-offline-oct6.json): a parent process installed
  seccomp network denial, confirmed AF_INET socket creation was refused, then ran
  the actual offline CLI in an inheriting child. Reports completed with five demo
  findings and AI disabled. This proves the prepared scan, not online setup.
- [Web-only evidence](evidence/kali-web-only-oct6.json): loaded `config/web-only.json`,
  supplied a temporary owned loopback HTTP server and its pinned scope, and ran the
  CLI. Internet mode, only the web module, one HEAD plus one GET, one asset and AI
  disabled were verified. No external deployment was contacted.

Real API acceptance remains NOT TESTED. The disclosed credential was not used or
saved to the repository. A privately configured replacement and confirmed free-only
account environment remain required; no paid calls are authorized. Local-model
testing remains deferred. This checkpoint does not accept a production release.

The owner requested online API AI using Groq `llama-3.1-8b-instant`, web-only
non-AI, and local offline non-AI. Local-model AI testing is deferred for now,
not silently marked accepted or removed from earlier release requirements.

## API AI

At source `7f8b08f`, the compatible-provider adapter supports an explicit
`response_format: "json_object"`; the Groq template enables it. Existing provider
configurations retain text mode unless selected. Advanced dashboard AI JSON can
carry the same option. Output still must pass the original strict schema, known
finding-ID and metadata-only disclosure checks. Invalid JSON, invented IDs and
unexpected executable fields remain rejected. This is remediation assistance,
not autonomous scanning or execution.

Kali's full suite passed **170 tests in 10.663 seconds** at that source, including
the new response-format/disclosure/schema tests. The session had no configured
`SECAUDIT_API_KEY` (presence only was checked). This proves fixture behavior, not
real Groq inference or free-quota billing. No provider call was made.

`config/groq-ai.json` is an explicit preparation template. It contains no key.
The endpoint follows [Groq's compatibility documentation](https://console.groq.com/docs/openai)
and the model is documented [here](https://console.groq.com/docs/model/llama-3.1-8b-instant).
Its empty `approved_ips` deliberately blocks execution until DNS pins are resolved
and reviewed on the execution host. Configure the credential privately through
`SECAUDIT_API_KEY`; never commit it. A key was disclosed in chat: rotate that key,
and do not paste its replacement into another message.

Initial acceptance uses only owned `demo/source` findings and sends finding ID,
rule and severity metadata. No source text or target captures are sent. Two
requests allow one model-list request and one inference request. The owner selected
**free quota only** on 6 October: no paid inference is authorized. Confirm that
the prepared account/test environment cannot fall back to billable usage before
calling the API. The template does not claim that a zero/default cost
ceiling enforces free-only billing. Real readiness, inference, JSON validation,
reports and failure/cancellation behavior remain to be verified on the prepared
provider. Local-model tests are not required for this immediate execution scope.

## Web-only, no AI

Use `config/web-only.json`: source is empty, only `web` is selected, AI is disabled,
and no online dependency/advisory module runs. Supply a reviewed authorization
scope and target; the empty target prevents accidentally scanning a sample website.

```bash
bash run.sh scan --config config/web-only.json \
  --target https://YOUR-AUTHORIZED-TARGET/ --scope /absolute/reviewed-scope.json
```

Existing controls still enforce IP pins, allowed paths and request/time budgets.
Only an explicitly owned/authorized target should be supplied. Built-in web checks
are bounded HTTP checks, not an interactive application or exploitation engine.
CI has exercised owned HTTP fixtures; intended-target acceptance is separate.

## Local machine only, no internet or AI

Use the existing offline source configuration with a local source path:

```bash
bash run.sh scan --config config/offline.json --source /absolute/local/source
```

With no target, no AI and no external/online modules, the built-in source path
denies network access through Linux seccomp. Initial dependency preparation may
need connectivity; prepare/install the offline bundle before disconnecting the VM.
The distribution CI already tests installation and scanning under inherited network
denial. Do not enable online advisories or API AI and call that an offline run.

## Missing inputs and current status

- SSH to the last supplied VM address timed out on 6 October. Start Kali and
  confirm its current reachable IP; repository location remains `/home/kali/Cyber-scan`.
- Privately configure a replacement API key, confirm the test budget, and make
  the environment available to the actual test process. A variable exported in
  an unrelated terminal does not reach a new SSH session automatically.
- Provide an authorized web target/scope only if deployment-specific testing is
  wanted now; otherwise the developer uses owned local fixtures on the VM.

No real API call was made and no VM acceptance was claimed in this preparation
checkpoint. Existing CI evidence remains tied to its recorded source. This scope
selection does not authorize release publication or waive owner acceptance.
