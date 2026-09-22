# v0.6.0 acceptance — in progress

Feature development is frozen apart from the explicitly requested static
authentication gap. Secaudit is a Linux governance, orchestration and evidence
wrapper over bounded built-in checks and optional isolated detection tools.

## Implemented, pending final CI acceptance

- Scope-bound static Bearer/cookie credentials referenced through environment variables.
- Header validation, HTTPS policy, rejection handling and process-local secret scrubbing.
- Negative tests for scanner crashes/malformed output, transport failures, disk-write
  failure and authentication boundary failures; full authenticated loopback CLI test.
- Coverage collection for CLI/dashboard child processes, with an 81% statement gate
  across every module in `secaudit`. No module exclusions added. The old 69% number
  omitted subprocess activity, so the comparison is not purely new test coverage.
- `integration/live_acceptance.py`: exactly one live OSV request, real Gitleaks positive
  and clean controls, plus real Bubblewrap network/read-only/environment/capability
  checks. Service or sandbox unavailability fails; no mocked substitute or skip.

## Environment and verification

Local Bubblewrap fails with `Failed to create NETLINK_ROUTE socket: Operation not
permitted`. No policy was disabled. Linux CI uses Ubuntu 22.04 with Bubblewrap and
Gitleaks 8.24.2, verified against its published release checksum. The downloaded
binary SHA-256 is included in acceptance output; release checksums are not a separate
publisher-signature verification. Live results and coverage are pending the Actions
run on the implementation commit. Unit tests do not certify live integrations.

## Remaining before v1.0

- Green live acceptance and statement coverage above 80% on the release commit.
- Browser interaction/accessibility acceptance for the existing dashboard.
- Distribution/repeat-install acceptance on supported Linux/Python combinations.
- A release checklist covering versioned artifacts, migration notes, known limitations
  and the trust model for unsigned bundles. No full pentest or compliance guarantee.

Login automation, role comparison, a new detection engine, real AI-provider support
and new scanning features remain outside this frozen milestone.
