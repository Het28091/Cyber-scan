# Expanded implementation and acceptance ledger

Updated 30 September 2026. This is unreleased work after v1.1.0, not a completed
expanded release. On 30 September the owner confirmed SCOPE/FINAL_HANDOVER as
the complete first-round requirements. The missing separate brief is no longer a
round-one blocker. See ROUND_ONE_HANDOVER.md for the consolidated implementation
handover and explicit remaining verification.

| Requirement | Implementation and evidence | Remaining acceptance |
|---|---|---|
| Independent non-AI modes | Existing offline/internet paths; provider and dashboard validators reject AI in both modes; `test_expanded.AIHardeningTests` verifies no transport call | Full Linux regression and owner-machine installation |
| Local/API AI | Provider validates config directly, enforces budgets, validates envelopes and model readiness, rejects duplicate/unknown suggestion IDs and registers API secrets for exact redaction | Real prepared Ollama model and configured API provider, including Linux cancellation end to end |
| AI trust | Only up to ten IDs, bounded rule identifiers and severities leave the process; free-form metadata is rejected. Suggestions remain separate from deterministic findings and never execute | Real-provider acceptance pending; no broader AI function is claimed |
| Dashboard | Gated AI modes, provider/budget JSON, explicit disclosure consent, scanner JSON, target workflow JSON, usage and suggestion downloads | Real browser acceptance of new controls and provider readiness failures |
| Session lifecycle | Explicit JSON credential POST; bearer-token verification, logout POST and invalidation GET; no redirects/retries or cookie persistence | Linux end-to-end run and owner review of the supported login protocol |
| Role comparison | Explicit role/account/URL/status matrix and bounded JSON-field assertions; expired credentials remain untested; response values are omitted from evidence | Arbitrary business workflows and complex authorization checks remain unsupported |
| Target browser | Pinned HTML fetched once; Chromium renders a snapshot inside Bubblewrap with no network and application scripting disabled; DOM counts only | Real Chromium/Bubblewrap acceptance is NOT TESTED; JS applications and interactive navigation remain unsupported |
| Active checks | Opt-in OPTIONS preflight with synthetic Origin; reflection with credentials is a candidate, not exploitation proof | Browser CORS exploitation and general active vulnerability testing remain unsupported |
| Detection breadth | Added constructed SQL and unsafe YAML syntax candidates with positive/clean controls; CORS and role fixture controls | See coverage table below; no comprehensive discovery claim |
| Reporting/frameworks | Persistent operator decisions and revision history; dashboard/CLI review and saved-run comparison; review JSON/HTML/PDF exports; AI usage provenance; WSTG role/CORS and ATT&CK mappings | Linux API/browser acceptance of review controls and confirmed requirement acceptance remain open |
| Delivery | Source provenance, acceptance-record gate, complete checksums and bounded archive validation implemented; source bundles include acceptance scripts | Real acceptance records, full CI, owner verification, final version and publication remain pending; the gated publisher is now implemented |

## First-round integration handover (UNVERIFIED)

Retained per-job preflight details, terminal report refresh through the queue and
CLI, selected/unselected module provenance, AI suggestions in technical exports,
PDF review due dates, acceptance scaffolding and exact-commit GitHub-gated
publication are implemented. The old v1.1 publishing marker is removed; CI builds
candidates and can be explicitly dispatched for future verification. No tests,
debugging or publication occurred in this pass. See [ROUND_ONE_HANDOVER.md](ROUND_ONE_HANDOVER.md).

## Running the supported workflows

### Assessment selection pass — 30 September 2026 (UNVERIFIED)

Dashboard source-module selection and assessment limits now feed the saved job
configuration, reusable profiles and configuration summary. This adds independent
OSV selection, local dataset paths/freshness, source traversal bounds, strict
optional-component requirements and required PDF output. Target/adapter modules
remain separately derived. No tests or debugging were performed. See
[ASSESSMENT_OPTIONS.md](ASSESSMENT_OPTIONS.md) for defaults and limits.

### AI discoverability and results pass — 30 September 2026 (UNVERIFIED)

Both AI mode choices now remain visible when disabled, with startup/setup guidance.
Dashboard, scan and doctor accept `--experimental-ai` as explicit process-level
opt-in; the existing environment gate remains. New dashboard AI drafts default to
required readiness. Reports show provider/model, readiness, inference status,
usage and untrusted suggestions linked to finding details. Non-AI modes remain
independent. No tests, debugging or real-provider calls were performed for this
pass. See [AI_QUICKSTART.md](AI_QUICKSTART.md) for setup and remaining boundaries.

### Reusable setup pass — 30 September 2026 (UNVERIFIED)

Added local assessment profiles with named/revisioned persistence, save-as-new,
update/load/delete controls and a readable configuration summary in the assessment
dialog. Profiles retain environment references, exclude ZIP content and consent,
and require fresh authorization/disclosure when loaded. Saving and previewing do
not start jobs or contact targets/providers. Structural validation is separate
from runtime preflight. See [ASSESSMENT_PROFILES.md](ASSESSMENT_PROFILES.md).
No tests, linting, runtime checks or debugging were performed for this pass.

AI remains gated by `SECAUDIT_EXPERIMENTAL_AI=1`. Edit `config/local-ai.json` or
`config/api-ai.json` with your prepared runtime/model, endpoint and literal IP
pins. API credentials stay in the named `SECAUDIT_...` environment variable.
CLI selection of an AI configuration authorizes the documented metadata disclosure;
the dashboard additionally requires its disclosure checkbox. No models are downloaded
by scanning. Model listing and inference each consume a request; budgets conservatively
reserve input bytes plus output ceilings, including the readiness request. Prices are
operator-supplied estimates, not provider billing verification. No retries are issued.

On Linux, with a synthetic source that produces at least one finding, set
`failure_policy` to `required` and run:

```sh
SECAUDIT_EXPERIMENTAL_AI=1 PYTHONPATH=. python integration/ai_acceptance.py \
  --config config/local-ai.json --evidence artifacts/local-ai-acceptance.json
```

Repeat with the reviewed API config. An empty suggestion list, unavailable provider,
missing model, incomplete reports or failed scan fails this acceptance command.
Supply API credentials securely to the environment; never put them in config or chat.
This command contacts the configured provider and does not install it.

Target workflows require `modules: ["target_workflow"]`, a `target`, a scope file,
and a `target_workflow` plan. Do not select `web` concurrently: workflow requests
share one explicit count/time budget, including login cleanup. Preflight validates
scope without sending a connectivity request. Scope must explicitly contain
`profiles: ["passive", "bounded"]`, reviewed origins/exclusions and current IP pins.
Existing passive scopes do not authorize login/logout POSTs or CORS probes.

Example plan for a controlled application, with every URL inside the scope:

```json
{
  "login": {
    "url": "https://owned.example/login",
    "credentials_env": "SECAUDIT_TARGET_LOGIN",
    "token_field": "access_token",
    "verify_url": "https://owned.example/private/me",
    "logout_url": "https://owned.example/logout"
  },
  "roles": [{
    "name": "reader",
    "url": "https://owned.example/private/admin",
    "authentication": {
      "type": "bearer", "env": "SECAUDIT_TARGET_READER",
      "origin": "https://owned.example", "paths": ["/private"]
    },
    "expected_status": 403
  }],
  "cors": ["https://owned.example/api"],
  "browser": {"urls": ["https://owned.example/login"]}
}
```

The login environment value is a JSON object of string credentials understood by
that application. Each value must contain 8..4096 characters; use dedicated test
accounts with sufficiently long identifiers. This avoids registering tiny strings
that would corrupt unrelated evidence during exact-value redaction. Successful
login must return a top-level bearer token; verification
must return 200; logout must return 200/204; the old token must then return 401/403.
HTTPS is required for credentials except IP-literal loopback fixtures. No form login,
MFA, OAuth, cookie-session negotiation or automatic refresh is implemented. If a login
response is lost/malformed, cancellation occurs or cleanup cannot be verified, revoke
the dedicated test session manually. Session creation and logout are the only planned
state changes. Never point these actions at unrelated production accounts.

Roles use separate existing environment credentials and compare response status, with
optional `response_assertions`, for example:

```json
"response_assertions": [
  {"path": ["tenant", "id"], "equals_env": "SECAUDIT_TARGET_EXPECTED_TENANT"},
  {"path": ["records", 0, "owner"], "equals_env": "SECAUDIT_TARGET_EXPECTED_OWNER"}
]
```

Each environment value is a JSON scalar (including quotes for a string). Paths have
at most twelve keys/array indexes; at most ten assertions are allowed per role.
Comparisons are type-sensitive. Missing fields and mismatches produce review
candidates; malformed responses/expectations or unexpected status leave assertion
coverage incomplete. Expected/observed values never enter evidence. Only assertion
indexes and match booleans are recorded. These checks add no extra HTTP requests.
No role is inferred from account names. A CORS OPTIONS response does not prove a
credentialed cross-origin read. Redirects are recorded, never followed. Every attempted
request consumes budget. An unavailable browser remains incomplete and blocks strict
workflows; no fallback disables Bubblewrap or Chromium's sandbox. Prepare Chromium
explicitly on Linux; optional `browser.executable` selects a trusted installed binary.
The snapshot browser receives neither account credentials nor provider environment.

After explicit browser preparation, exercise the real renderer and its script/network
negative controls on Linux (a failure is a blocker, never a reason to disable isolation):

```sh
PYTHONPATH=. python integration/target_browser_acceptance.py \
  --executable /path/to/prepared/chromium \
  --evidence artifacts/target-browser-acceptance.json
```

The existing mandatory dashboard browser CI script now also exercises gated provider
controls, disclosure consent, invalid scanner configuration, a local protocol fixture
through reports, and missing-model failure. These additions have not been run here;
the protocol fixture never counts as real-model acceptance.

Dashboard scanner JSON uses the CLI's existing `executable`, `rules`, and `cache`
options, for example `{"semgrep":{"rules":"/opt/reviewed/rules.yml"},"syft":{}}`.
Only the authenticated local operator should configure trusted executable paths.
Missing tools/data are recorded by preflight; selecting them does not prove coverage.

## Selected detection and mapping coverage

### Feature-first declaration expansion — 30 September 2026 (UNVERIFIED)

The next implementation pass adds JSON OpenAPI checks for anonymous alternatives,
missing local security schemes, cleartext server declarations, query API keys and
selected OAuth flows. It also adds Kubernetes JSON workload checks for explicit
host namespaces, service-account token mounting, host filesystem volumes,
privileged mode, privilege escalation, root users and broad capabilities.

Findings carry JSON-pointer evidence and flow through existing reports and
remediation tracking. Workload declarations enter the asset inventory. Runtime,
reference and parser limitations are recorded as events. No tests, linting,
runtime checks or debugging were performed for this pass. The earlier coverage
table below describes the preceding verified/fixture baseline; the new rule
catalogue and explicit boundaries are in [DECLARATION_CHECKS.md](DECLARATION_CHECKS.md).

| Area | Checks and controls | Explicit gaps |
|---|---|---|
| Python source | Existing eval/exec, shell and pickle candidates; new `PY-SQL-DYNAMIC`, `PY-YAML-LOAD` positive/clean controls | No taint proof, aliases or general interprocedural analysis; constructed execute arguments may not be SQL |
| Web/API | Existing headers/cookies/OpenAPI declarations; new credentialed CORS preflight and role-status fixtures | No general injection, XSS, CSRF, SSRF, business logic or complete OpenAPI validation |
| Dependencies | Existing pinned inventories, local advisories, OSV and isolated adapters | Only known supported manifest/advisory coverage; unknown versions stay unresolved |
| TLS/configuration | Existing verified TLS transport, HSTS, debug, verification-disabled and Docker USER heuristics | No protocol/cipher audit, container image or broad IaC coverage |
| Browser | Static snapshot DOM inventory | No JS execution, interactive login, screenshots or browser-only exploit confirmation |
| Frameworks | NIST CSF 2.0 ID.RA-01; four WSTG 4.2 rules (HSTS, cookies, roles, CORS); one ATT&CK technique (T1552.001) | All other controls/techniques unmapped; no certification or execution sequence |

Mappings retain `NEEDS MANUAL REVIEW`. ATT&CK T1552.001 relates a credential-literal
candidate to possible credentials-in-files exposure; it does not assert attacker
activity. Official references and the reviewed snapshot hash are included in reports.

## Operator review and remediation retests

Findings now have a separate operator-review workflow. Open a finding in the dashboard
to record status, rationale, remediation owner, evidence reference and an optional
retest run. Scanner findings and their validation status are not rewritten. Decisions
are stored in `reviews.sqlite3` as append-only revisions; concurrent stale edits are
rejected. The local operator can reopen any decision. This is an audit trail within
an operator-owned workspace, not tamper-proof or multi-user identity assurance.

Supported states: OPEN, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK,
REMEDIATION_PENDING, RETEST_REQUESTED and RESOLVED. Every decision requires a
rationale. Confirmed, false-positive, accepted-risk and resolved decisions also
require a reviewed evidence/verification reference. Resolution requires a completed,
later retest with matching assessment context, no explicitly incomplete/skipped
coverage and no repeated or moved observation. It still requires the operator's
verification; absence from heuristic results is never an automatic fix confirmation.

The Reports view compares saved runs and downloads the current review history.
Comparisons label repeated, possibly moved, new, not-observed and not-retested
findings without changing review status. Older releases lack assessment context
and cannot establish resolution through this mechanism. Source-root changes
(including separately extracted ZIP directories) are conservatively non-comparable.
Matching context does not prove identical rule/database versions or exhaustive coverage.

CLI equivalents, using a locally prepared decision JSON file:

```sh
python -m secaudit review RUN_ID FINDING_ID --output runs --decision decision.json
python -m secaudit compare BASELINE_RUN_ID RETEST_RUN_ID --output runs
python -m secaudit resume RUN_ID --output runs
```

Example decision: `{"revision":0,"status":"CONFIRMED","note":"Reviewed the call
site","evidence":"app.py:12","owner":"maintainer"}`. Use the returned revision
for subsequent edits; do not put credentials in notes or evidence references.
`resume` explicitly regenerates report snapshots, including current operator review
in technical HTML/Markdown and executive/technical PDF plus `operator-review.json`.
Existing downloaded reports do not update automatically. Review/compare do not send
target traffic or invoke AI. Failed AI readiness attempts now retain request/token/cost
reservation accounting in preflight and run provenance.

## Verification recorded in this work session

### Subsequent feature-first pass — 30 September 2026 (UNVERIFIED)

The owner requested spiral development: build the full project first and defer
testing/debugging. No tests, linters, runtime checks or debugging were performed
for this subsequent pass. The results below predate the guided dashboard changes.

The assessment dialog now defaults to guided fields for authorization references,
authorized/excluded URL prefixes, target IP pins, request/time limits, test-account
login/verification/logout, removable role probes, CORS URLs, browser snapshot URLs
and executable, scanner selection/paths, and experimental provider settings.
Role credential scopes are derived from each explicit URL. Credentials remain
server environment references. Bounded profiles are selected when workflow
operations are configured. Backend policy validation remains authoritative.

Advanced JSON remains selectable for configurations beyond these guided fields,
including response assertions, static scope authentication and detailed provider
cost/context settings. Switching editors does not import JSON into guided fields;
guided submission writes its values into the JSON fields before posting. No
interactive JavaScript browser, new detection engine, real provider acceptance,
owner acceptance or stable release is claimed by this UI implementation.

### Earlier verification (before the guided dashboard pass)

The subsequent remediation work-list implementation is also **UNVERIFIED** and
is not covered by the earlier results below. It adds optional ISO `due_date`
values to append-only operator decisions, UTC overdue calculation, priority-sorted
action plans, owner/status/due-date filters in Reports & evidence, finding-detail
links, and current JSON/CSV downloads. Existing decisions without due dates remain
undated. Accepted risk, false positives and resolved records are excluded from
overdue/unassigned action counts; risk acceptance does not mean remediation.

Current plans use the latest review revisions when requested; previously downloaded
reports remain snapshots. The plan includes remediation text, retest instructions,
operator rationale, evidence references, linked retest IDs and scanner validation
status. Downloads contain the complete selected assessment, independently of the
dashboard's display filters. CSV cells guard against spreadsheet formula prefixes.
No new scan, target request or AI call is made by exporting a plan.

```sh
bash run.sh remediation RUN_ID --output runs > remediation-plan.json
bash run.sh remediation RUN_ID --output runs --format csv > remediation-plan.csv
```

CLI review decision JSON may include `"due_date": "2026-10-14"`; an empty string
clears the date. Existing revision, evidence and retest requirements still apply.
The authenticated API exposes `GET /api/runs/RUN_ID/remediation`, with `.json`
and `.csv` download variants. These exports require a terminal saved run.

### Historical check results

- Windows Python 3.12.14: 47 selected tests, 46 PASS and 1 Linux-only SKIP.
- Expanded suite: 19 tests, 18 PASS and 1 Linux-only SKIP; review workflow: 9 PASS;
  release gate/integrity suite: 10 PASS. Synthetic acceptance records test the
  validator and do not count as real release evidence.
- Review checks include persistence/reopening, stale writes, chronology, incomplete
  retests, redaction, real CLI commands and real PDF-generation smoke checks.
- Linux API tests now cover review CSRF, persistence and stale revisions; dashboard
  browser acceptance covers saving a review. These Linux checks remain NOT TESTED here.
- Ruff 0.11.13 correctness gate: PASS (including integration scripts).
- Bandit 1.8.6 high-severity/high-confidence gate: PASS; lower-severity results
  are not a claim of zero issues.
- Dashboard JavaScript syntax: PASS using Node 24.19.0.
- WSL: not installed. Full Linux suite, kernel isolation, Chromium/Bubblewrap,
  real providers, owner acceptance and expanded release: NOT TESTED.

Fixture protocol tests are not real-provider or real-browser acceptance. The
historical v1.1.0 evidence is retained and does not validate these changes.

See [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md) for the enforced stable-build and
collection gate, evidence formats and remaining publication requirements.
