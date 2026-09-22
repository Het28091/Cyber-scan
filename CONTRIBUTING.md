# Contributing

Use Python 3.11+ on Linux. Run `make test` and `make demo` before proposing changes.
Use synthetic fixtures and local servers; never run CI against public targets.
Update the capability matrix and verification record whenever behavior changes.
Keep unsupported checks explicitly NOT TESTED. Preserve evidence provenance and
never turn absent data or scanner errors into a passing assessment.

Network-capable adapters require independent scope and egress tests. Third-party
scanner adapters require kernel-enforced isolation, supported-version detection,
input/output schema tests, cancellation and timeout coverage. Avoid shell commands
constructed from target-controlled strings. Never commit secrets or real reports.
