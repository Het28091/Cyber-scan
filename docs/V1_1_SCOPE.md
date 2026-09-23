# v1.1 scope — verify existing scanner integrations

Stable v1.0 remains available. The next milestone closes verification gaps in the
existing orchestration layer; it does not add AI, active exploitation or broaden
target authorization.

First increment: real Semgrep 1.175.0 in mandatory Bubblewrap, local operator rules,
Python/JavaScript positive controls, clean controls and malformed-rule rejection.
It must retain network isolation, read-only input, cleared environment and resource
bounds. Install tool dependencies under `/usr` so the sandbox can resolve their
interpreter and libraries; do not mount the operator's home or disable isolation.

Acceptance is pending until the real CI job passes. Installation is an explicit
connected preparation step. The Semgrep top-level version is pinned; its transitive
installation dependencies are not hash-locked. This is not yet a certified offline
Semgrep distribution or a general detection-quality benchmark.

Later increments: Syft inventory and Trivy/local-database verification, then decide
which verified tools should be offered through supported dashboard presets. Those
remain deferred until their own acceptance passes. No automatic rescan of Grid Guard.
