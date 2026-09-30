# Contributing

## Development management

Follow [the five-spiral plan](docs/FIVE_SPIRAL_PLAN.md) and
[current project status](docs/PROJECT_STATUS.md). The next planned execution phase
is Spiral 2 functional validation/repair; the first round's code is assembled but
not production-accepted. Use [the developer prompt](docs/DEVELOPER_PROMPT.md) to
start a phase and record its task IDs, evidence, blockers and exit decision.

Routine development follows the validation guidance below when testing is
authorized. Planning-only tasks do not start runtime tests. If the owner defers
testing, mark implementation unverified and leave readiness gates open. Do not
expand features to avoid unresolved acceptance or operational defects.

## Implementation and verification

Use Python 3.11+ on Linux. Run `make test` and `make demo` before proposing changes.
Use synthetic fixtures and local servers; never run CI against public targets.
Update the capability matrix and verification record whenever behavior changes.
Keep unsupported checks explicitly NOT TESTED. Preserve evidence provenance and
never turn absent data or scanner errors into a passing assessment.

Network-capable adapters require independent scope and egress tests. Third-party
scanner adapters require kernel-enforced isolation, supported-version detection,
input/output schema tests, cancellation and timeout coverage. Avoid shell commands
constructed from target-controlled strings. Never commit secrets or real reports.
