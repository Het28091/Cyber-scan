# Current scope — Linux assessment with optional AI

Updated 29 September 2026. Final delivery target: **14 October 2026**.
The owner restored the original project scope, including AI and non-AI modes.
The earlier non-AI-only freeze is superseded. The implementation and acceptance
matrix is maintained in [FINAL_HANDOVER.md](FINAL_HANDOVER.md).

## Published baseline

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

These items are planned, not claims of current functionality. AI remains
experimental until its gates pass. Previously deferred functionality is reopened
for this delivery; the original brief must be reconciled before final sign-off.

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
