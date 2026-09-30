# First spiral round — implementation handover

30 September 2026. The owner confirmed that **SCOPE.md and FINAL_HANDOVER.md are
the complete requirements for round one**. A separate missing original brief is
therefore not a blocker for this round. It is not a claim about unspecified future
features or a waiver of the recorded final acceptance requirements.

**Round-one implementation is assembled for the bounded functionality below.**
This means there is an implementation path across the documented workstreams,
with the remaining integration code now added. It does not mean the application
has passed end-to-end testing. The owner explicitly deferred testing/debugging;
the recent implementation, including this integration pass, is **UNVERIFIED**.
The final tested/released project goal is not yet complete.

## Requirement traceability

| Documented workstream | Implemented first-round path | Boundary / next-round evidence |
| --- | --- | --- |
| Linux setup and independent non-AI modes | Setup, offline/internet configurations, source/ZIP/target input, module selection, isolation and preflight | Linux install/regression/owner validation remains open |
| Local AI | Ollama adapter, model readiness, explicit opt-in, pinned loopback, budgets and failure policy | Prepared real model and failure/cancellation verification required |
| API AI | Compatible model-list/chat adapter, HTTPS pins, environment credentials, disclosure and budgets | Actual provider compatibility and end-to-end verification required |
| AI trust and reporting | Bounded metadata-only suggestions, schema validation, finding links, UI/JSON/technical HTML/Markdown/PDF output | No autonomous source analysis, tool execution or finding confirmation |
| Dashboard | Guided/JSON setup, visible AI modes, scanner/module choices, limits, profiles, summaries, jobs, cancellation and saved diagnostics | Browser and accessibility acceptance of recent controls required |
| Authentication and role workflow | Scoped static credentials, JSON bearer login, verification/logout/invalidation, role status and field assertions | Explicit test accounts only; no OAuth/MFA/form-session negotiation or arbitrary business workflow |
| Target browser / active checks | Explicit pinned URL fetches, isolated static Chromium snapshots, bounded CORS probes | Static HTML only; no application JS execution or browser exploitation proof |
| Detection breadth | Python syntax, secrets, config, OpenAPI/Kubernetes JSON, inventory/advisories, external adapters, web headers/cookies and verified TLS transport | Heuristics and selected declarations; no exhaustive SAST, general IaC or TLS cipher audit |
| Assessment lifecycle | Configure → queued/running job → preflight → selected checks/coverage → evidence/report snapshots → operator review → retest comparison | Job failures retain preflight; current and downloaded snapshots are distinguished |
| Remediation | Owners, due dates, rationale, evidence references, revision history, current action plans and report refresh | Resolution requires operator evidence and eligible matching retest; missing observations alone never resolve findings |
| Framework traceability | Reviewed mapping snapshot, report exports, documented coverage/unmapped areas | Partial NIST/OWASP/MITRE related-evidence mappings, not compliance certification |
| Delivery | Source packaging, exact-commit acceptance records, full stable bundle collection, GitHub CI verification and explicit publication command | Actual acceptance, final unused version, stable bundles and publication belong after round-two verification |

No unsupported browser, AI, detection or authentication capability is silently
counted as implemented. The scope documents ask for bounded workflows and selected
coverage, not exhaustive vulnerability discovery. Additional breadth is future
work unless the owner expands these requirements.

## Final integration added in this handover

- Jobs retain a per-job preflight result, including blocked readiness. **Assessments
  → Details** exposes component status/resolution even when no run was created.
  Job records retain the latest 200 terminal jobs; evidence runs are not pruned.
- **Reports & evidence → Refresh report snapshots** queues a terminal-run export
  using saved evidence and current reviews. It makes no target/provider requests.
  Jobs are serialized with scans, and duplicate active work for the same run is
  rejected. Cancellation may leave a mixture of previous and newly written report
  files; run refresh again after the job finishes if needed.
- CLI `export-reports RUN_ID --output runs` provides terminal-only report refresh;
  `resume` remains the explicit recovery operation for interrupted state.
- Report metadata records snapshot generation, and new assessments record selected
  and unselected modules. Technical exports include untrusted AI suggestions; PDF
  operator reviews include due dates.
- `scripts/acceptance-records.py` creates NOT TESTED envelopes and seals reviewed
  records without manufacturing PASS status. `scripts/publish-release.py` checks
  exact-commit acceptance and real GitHub CI before collecting/publishing assets.
  Ordinary pushes only build candidates; no old commit marker publishes a release.

## Owner start point

On your existing Linux checkout, stop the dashboard and update:

```bash
git pull --ff-only origin main
bash setup.sh
bash run.sh dashboard --experimental-ai --output runs
```

The flag exposes optional AI modes; it does not require AI for ordinary scans.
Follow [TEST_CHECKPOINT.md](TEST_CHECKPOINT.md) for the initial manual pass, then
[AI_QUICKSTART.md](AI_QUICKSTART.md) for prepared providers. Use existing dedicated
fixtures/accounts for authenticated flows. Do not interpret a missing optional
tool/model as successful coverage.

## Round two — verification and improvement

**Planning update:** the following was the original combined follow-up list. It
is now allocated across Spirals 2–5 in [FIVE_SPIRAL_PLAN.md](FIVE_SPIRAL_PLAN.md).
Use that plan's risk order, task IDs and exit criteria for new development;
this historical handover does not require all release work in Spiral 2.

1. Run Linux setup, automated suites and mandatory CI; resolve actual failures.
2. Exercise non-AI modes, current dashboard controls, profile reloads, cancellation,
   retained preflight failures, review/retest and report refresh in a real browser.
3. Run real local/API AI acceptance, including unavailable models, malformed output,
   budgets, redaction and cancellation. Record actual provider identities.
4. Exercise session/role/CORS and Chromium/Bubblewrap acceptance; validate new
   declaration rules against positive and clean examples.
5. Reconcile requirement/coverage results with the owner, choose an unused final
   application version, and gather acceptance against that final source commit.
6. Build the four stable Linux/Python bundles and use the gated publication path.

No tests, debugging, CI dispatch, provider requests, version bump or release
publication were performed for this handover pass. GitHub commits labelled
`[skip ci]` are build checkpoints and cannot satisfy the publisher's CI gate.
