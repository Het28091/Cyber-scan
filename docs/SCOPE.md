# Current scope — Linux non-AI milestone

## Agreed direction

Linux only. Run locally with an automatic virtual environment and a local dashboard.
Internet access during a non-AI scan is allowed. The first milestone is deterministic
assessment without model installation, tokens, provider keys or AI reasoning.
Strict-offline execution remains a separate option.

## Included

- Native Linux setup/launch, pinned PDF dependencies and mandatory preflight.
- Authorized local/public URL checks with exact scope and DNS pins.
- Bounded crawl, HTTP headers, cookie attributes and HTTPS certificate validation.
- Read-only Python/config/secret checks, ZIP inputs and JSON OpenAPI inventory.
- Basic Python/npm package inventory and optional online OSV advisory queries.
- Local advisory snapshots for offline dependency checking.
- Local authenticated dashboard, queue, cancellation, evidence exploration and reports.
- Explicit coverage, network disclosure, redaction and reproducible synthetic tests.

## Network permissions

Internet mode permits only the scoped target client and the selected fixed advisory
provider. No AI request is allowed in this mode. OSV receives only package ecosystem,
name and version; its response is data and cannot execute commands. There is no
ambient network permission for arbitrary subprocesses or scanned project code.
Private package identities should use offline snapshots instead of OSV.

Target authorization does not expand through links, redirects or advisory content.
Scanner installations and updates remain explicit preparation tasks. Offline mode
rejects public target IPs and online dependency modules. Local target hostname DNS
uses the system resolver; disconnected deployments should use local DNS/IP literals.

## Deferred

Real external-tool certification, browser-assisted testing, dedicated-account role
comparisons, active test profiles, broad container/IaC coverage, complete framework
assessments and real AI-provider validation. No autonomous exploitation, persistence,
credential attacks, destructive actions or compliance certification are promised.

## Acceptance evidence

See PROGRESS.md and VERIFICATION.md. A passed fixture test is not a successful live
provider test. A usable first pipeline is not complete security coverage.
