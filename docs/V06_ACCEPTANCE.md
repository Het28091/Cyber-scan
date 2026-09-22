# v0.6.0 acceptance — passed

Feature development is frozen apart from the explicitly requested static
authentication gap. Secaudit is a Linux governance, orchestration and evidence
wrapper over bounded built-in checks and optional isolated detection tools.

## Implemented and verified

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
publisher-signature verification. Live acceptance and unit/security jobs both passed on
[commit 337d23c](https://github.com/Het28091/Cyber-scan/commit/337d23cbbbf0e9ce62367f7bf7adc2f0d9241bb9),
[Actions run 35758735153](https://github.com/Het28091/Cyber-scan/actions/runs/35758735153).
[Machine-readable evidence](evidence/v0.6-live.json) records the host, timestamps,
binary checksum, counts and boundary results.

- Live OSV: one request/response, one completed query, ten advisories, no failures/skips.
- Gitleaks 8.24.2: one synthetic-secret finding; zero findings on the clean control.
- Sandbox network namespace, read-only source, cleared credentials and dropped capabilities: PASS.
- Unit/integration suite: 100 tests passed; 93% statement coverage (1,562 statements,
  108 missed). Ruff, Bandit, pip-audit and offline demonstration also passed.

Actual execution exposed two previously hidden bugs: Gitleaks' WASM regex runtime
could not reserve 4 GiB within the generic 2 GiB address limit, and `/dev/stdout`
was not its supported stdout report sentinel. The adapter now uses a finite 8 GiB
virtual-address ceiling for Gitleaks and `--report-path -`. Other tools retain 2 GiB;
all other limits and isolation controls remain. This is not a resident-memory limit.

The first CI run also exposed a unit test depending on host Bubblewrap availability;
the negative crash fixture now isolates that dependency. Live acceptance always
executes the actual sandbox and binary. Semgrep, Trivy and Syft remain fixture-tested;
the v0.6 requirement was at least one real external tool.

## Remaining before v1.0

- Keep live acceptance and the 81% coverage gate green for every release candidate.
- Browser interaction/accessibility acceptance for the existing dashboard.
- Distribution/repeat-install acceptance on supported Linux/Python combinations.
- A release checklist covering versioned artifacts, migration notes, known limitations
  and the trust model for unsigned bundles. No full pentest or compliance guarantee.

Login automation, role comparison, a new detection engine, real AI-provider support
and new scanning features remain outside this frozen milestone.
