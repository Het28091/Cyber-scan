# Selecting checks and limits

Feature-first implementation, 30 September 2026. **UNVERIFIED:** no tests,
runtime checks or debugging were performed for this pass.

The assessment dialog now has **Checks and assessment limits**, shared by the
guided and advanced editors. It controls:

- Python syntax-pattern candidates (`source`).
- Credential-literal candidates (`secrets`).
- Configuration and Kubernetes JSON checks (`config`).
- OpenAPI JSON declaration checks (`openapi`).
- Local dependency advisory matching (`dependencies`).
- OSV package queries (`online_dependencies`), available only in internet/no-AI mode.

Target configuration separately adds passive web checks or the explicit target
workflow. External scanner selections separately add their adapter modules. To
assess only a target, clear the source directory and deselect source checks. An
empty source-module selection is permitted when a target or external scanner
provides at least one executable module. A configuration with no module is rejected.

Internet access no longer implies that the operator must use OSV: deselect its
module to avoid package queries while retaining scoped public target access.
Changing away from internet mode clears and disables OSV selection; switching
back does not silently restore it. AI is independent of these source selections
and assists with the resulting findings when enabled and available.

Under **Source limits and required components**, configure:

| Setting | Default | Supported bound |
| --- | --- | --- |
| Source files | 5,000 | 1–50,000 |
| Bytes per source file | 1,000,000 | 1–10,000,000 |
| Total source bytes | 50,000,000 | 1–500,000,000 |
| Source traversal seconds | 60 | 1–300 |
| OSV package queries | 25 | 1–100 |
| Local dataset age in days | 30 | 0–36,500 |

These source limits do not replace the separately configured target-request or
provider budgets. The dashboard ZIP upload limit remains 10 MB. Choose a prepared
local advisory dataset path when enabling local matching; source scans do not
download it. See [DATASETS.md](DATASETS.md) for dataset preparation.

**Require selected optional scanners and data** applies the existing strict-mode
policy: missing selected tools/data can block preflight rather than being skipped.
**Require PDF renderer** blocks when the PDF prerequisite is absent. Stale dataset
blocking uses the existing freshness policy; combine it with strict mode when a
fresh local advisory dataset is mandatory. These toggles do not install anything
or turn partial heuristic coverage into complete coverage.

Profile save/load and configuration review include these choices. Profiles created
before this change load the source-module defaults for their stored preset. The
backend accepts `modules` (source-module names only) and `assessment_options`
(the listed limits and policies). Target/adapter modules are derived separately.
CLI configuration continues to use its existing top-level `modules`, `max_files`,
`strict` and related fields; the nested object is a dashboard/profile API format.

Unselected checks are not evidence of a clean assessment. Source declaration
inventory can still be collected during source traversal even when advisory
matching or OpenAPI checking is deselected.
