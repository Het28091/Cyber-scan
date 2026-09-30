# Current scope — Linux assessment with optional AI

**First spiral round:** the implementation is assembled for the bounded scope
below. The owner confirmed SCOPE.md and FINAL_HANDOVER.md as the complete
round-one requirements on 30 September 2026. See
[ROUND_ONE_HANDOVER.md](ROUND_ONE_HANDOVER.md) for implementation traceability,
supported limits and the round-two verification list. Recent code is UNVERIFIED;
the final tested/released goal is not complete.

Updated 29 September 2026. Final delivery target: **14 October 2026**.
The owner restored the original project scope, including AI and non-AI modes.
The earlier non-AI-only freeze is superseded. The implementation and acceptance
matrix is maintained in [FINAL_HANDOVER.md](FINAL_HANDOVER.md).

## Published baseline

### Current implementation approach — 30 September 2026

The owner requested feature-first spiral development: assemble the end-to-end
project first, then improve it in later iterations. Testing and debugging are
deferred at the owner's request. Newly added features are **unverified**; historical
results do not validate this pass or close expanded acceptance requirements.
The dashboard now includes guided configuration for the implemented target,
scanner and AI workflows, with advanced JSON retained for detailed options.
The next spiral pass adds a remediation work list, review due dates, owner/status
filters and current action-plan exports through the dashboard and CLI. Both
feature-first passes remain unverified.
The detection pass additionally implements JSON OpenAPI and Kubernetes declaration
checks, documented in [DECLARATION_CHECKS.md](DECLARATION_CHECKS.md). This pass is
also unverified and does not provide runtime or broad IaC assurance.
Reusable local assessment profiles and a configuration-summary panel are now
implemented in a further unverified pass; details are in
[ASSESSMENT_PROFILES.md](ASSESSMENT_PROFILES.md).

v1.1.0 provides Linux setup and preflight, source/ZIP and passive URL assessments,
static scoped authentication, package inventory/advisories, verified external
scanner integrations, dashboard workflows and evidence/report exports.
Its published verification applies to that baseline only.

## Expanded delivery scope

- Preserve independent offline and internet-enabled non-AI workflows.
- Complete optional local-model and API-model assistance, including real-provider
  acceptance, provider readiness, budgets, disclosure and failure handling.
- Add dashboard access to supported AI workflows and scanner configurations.
- Develop controlled login/session, role-comparison and target-browser workflows.
- Add bounded non-destructive active checks and broaden detection coverage.
- Reconcile original workflow, reporting, remediation and framework requirements
  against implemented features and test evidence.
- Finish owner-machine verification and publish a versioned, gated release.

Implementation coverage for these workstreams is recorded in the round-one
handover. AI remains experimental until its gates pass. Verification, owner
acceptance and final publication remain pending; implementing a path does not
prove it works or close an acceptance gate.

The unreleased implementation and explicit remaining gaps are tracked in
[EXPANDED_IMPLEMENTATION.md](EXPANDED_IMPLEMENTATION.md). Provider hardening,
dashboard controls and bounded target workflows now have code and fixture tests;
this does not close real-provider, Linux/browser, requirements or owner acceptance.

## Network and evidence boundaries

Non-AI modes must never call an AI provider. Strict-offline mode must retain its
network restrictions. Local AI and API AI need separately documented data flows.
Scoped targets, advisory services and approved providers do not grant arbitrary
network access to uploaded code or subprocesses. Downloads occur during explicit
preparation. Secrets remain environment references and are redacted from evidence.

Target authorization does not expand through links or redirects. New active and
authenticated tests use controlled fixtures first; production tests require
appropriate scope and test accounts. AI output is untrusted assistance, not proof
of a finding or authority to execute commands.

## Completion rules

See [delivery plan](FINAL_HANDOVER.md), [progress](PROGRESS.md) and
[verification](VERIFICATION.md). Report unsupported checks explicitly.
No guarantee of exhaustive vulnerability discovery, autonomous destructive
exploitation or compliance certification is made.
