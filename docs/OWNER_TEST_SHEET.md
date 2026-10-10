# Owner test sheet — unverified build handover

Owner direction, 10 October: continue implementation without further agent-run
tests; the owner will test. Leave each result NOT TESTED until actually exercised.
This sheet is supporting evidence, not a substitute for the final ten gate records.

Record: source commit ______; candidate/archive hash ______; Linux/Python ______;
operator/date ______; private evidence directory ______.

## Prepare separate modes

From the prepared Linux checkout, the new helper can generate separate configs
and evidence directories without running any scan or network request:

```sh
PYTHONPATH=. .venv/bin/python scripts/prepare-owner-modes.py \
  --source /absolute/owned-source \
  --target https://AUTHORIZED-TARGET/PATH \
  --scope /absolute/reviewed-scope.json \
  --api-config /absolute/reviewed-api.json \
  --destination /absolute/new-owner-workspace
```

The helper is **IMPLEMENTED_UNVERIFIED**. Review its generated configs before use.
The destination must be new and outside the scanned source. API mode uses the
owned source, the supplied provider configuration and required-provider failure
policy; it does not run a parallel web assessment. Use the generated README commands.
The credential stays in its configured environment variable; free-only billing
must be enforced by the prepared account. Templates with empty provider pins are
not ready configs. No credentials should be put into this sheet or committed.

## Record actual results

| Journey | Expected behavior | Result / run ID / notes |
| --- | --- | --- |
| Offline local | Works after dependencies are prepared with internet disconnected; AI disabled; owned positive and clean examples match expected rules | NOT TESTED |
| Web-only | Uses only reviewed current target/IP/path scope; AI disabled; records authentication/coverage limits; reports available | NOT TESTED |
| Online API AI | Advertised model and real inference work within configured free-only limits; suggestions reference existing IDs; findings remain unchanged | NOT TESTED |
| AI failure | Missing key/unavailable provider is clearly blocked or failed; no fabricated suggestions or successful acceptance | NOT TESTED |
| Profiles/restart | Save a profile; restart dashboard; reload correct mode/limits without saved credential values | NOT TESTED |
| Job lifecycle | Observe completion/cancellation and retained partial evidence; no stuck active job after normal restart | NOT TESTED |
| Review/retest | Assign owner/due date; update review; rerun owned fixture; compare results without changing original findings | NOT TESTED |
| Reports | Download HTML/JSON/PDF; refresh reflects review changes; original scanner evidence remains immutable | NOT TESTED |
| Recovery | Stop writers; back up and restore into a new directory; verify findings, review history and profiles | NOT TESTED |

Use `bash run.sh dashboard --experimental-ai` for an AI-enabled local dashboard;
without that flag AI remains disabled. Follow OPERATIONS.md for maintenance.
Keep the dashboard loopback-only. Use authorized fixtures for all target actions.
Report a problem with source/run ID, mode, expected/actual behavior and redacted
logs. Do not paste cookies, API keys or private captures.

## Decisions still needed

- Accept supported detection limits, including passive web checks and metadata AI.
- Identify representative workloads and approve operating budgets.
- Identify independent reviewer and retain their actual findings.
- Decide retention/backup schedule, support contact and release observation period.
- Resolve the deferred local-model gate under the existing release policy.
- Record final go/no-go only after exact-commit gates and final evidence exist.

Owner decision: PENDING. Signature/date: ______. Release authorization: NOT GIVEN.
