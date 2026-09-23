# v1.1 scope — verify existing scanner integrations

Stable v1.0 remains available. The next milestone closes verification gaps in the
existing orchestration layer; it does not add AI, active exploitation or broaden
target authorization.

First increment: real Semgrep 1.175.0 in mandatory Bubblewrap, local operator rules,
Python/JavaScript positive controls, clean controls and malformed-rule rejection.
It retains network isolation, read-only input, cleared environment and resource
bounds. Install tool dependencies under `/usr` so the sandbox can resolve their
interpreter and libraries; do not mount the operator's home or disable isolation.

Semgrep acceptance passed in [run 35841479704](https://github.com/Het28091/Cyber-scan/actions/runs/35841479704);
see [durable evidence](evidence/v1_1-semgrep.json). Installation is an explicit
connected preparation step. The Semgrep top-level version is pinned; its transitive
installation dependencies are not hash-locked. This is not yet a certified offline
Semgrep distribution or a general detection-quality benchmark.

Later increments: Syft inventory and Trivy/local-database verification, then decide
which verified tools should be offered through supported dashboard presets. Those
remain deferred until their own acceptance passes. No automatic rescan of Grid Guard.

The next acceptance increment exercises Syft 1.52.0 and Trivy 0.74.0 on
Ubuntu 22.04 x86_64. Binary SHA-256 digests are pinned in CI from the official
release assets. Trivy DB preparation is explicitly connected; all adapter scans
use the mandatory network-isolated sandbox and a read-only DB. These checks
remain pending until a successful CI result is recorded. Checksums establish
artifact identity, not an independent code audit or signature verification.

The synthetic fixture is an npm lockfile containing lodash 4.17.20. Acceptance
requires Syft to inventory that exact component and Trivy to report
CVE-2021-23337, then verifies empty input and the full offline PDF pipeline.
No dependency is installed from the fixture and no external target is scanned.
Syft's external CycloneDX inventory is retained separately; it is not silently
merged into the built-in inventory or OSV queries.

Release selection reviewed the upstream Trivy incident advisory
[GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23).
The compromised 0.69.4 release and mutable Trivy Actions are not used.
