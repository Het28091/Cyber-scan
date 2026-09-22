# Offline advisory snapshots

The built-in matcher deliberately supports exact enumerated affected versions only.
It does not infer semver ranges or claim full ecosystem coverage. Inventory supports
exact requirements.txt pins and npm package-lock v2/v3 packages. Transitive Python
packages not listed in the file are absent from that inventory.

Input is a JSON array. This is a synthetic example, not a real advisory:

```json
[{"id":"DEMO-001","ecosystem":"PyPI","name":"example-package","affected_versions":["1.0.0"],"summary":"Synthetic demonstration only","source":"urn:secaudit:demo","severity":"MEDIUM","remediation":"Review the operator-supplied advisory."}]
```

`dataset` validates a staged snapshot before publication and refuses existing
output/manifest files. Use a new versioned filename when refreshing data.
It builds a sibling `.manifest.json` with schema 1, version, source,
publication timestamp, SHA-256, and an explicit unsigned-provenance notice. Runtime
validates every record and the hash. Default freshness window is 30 days;
`dataset_max_age_days` changes it. `block_stale_data` with a required module blocks
stale input; otherwise staleness remains visible. Hash integrity does not establish
that an advisory is genuine. Review source provenance and redistribution terms.

No real vulnerability database is bundled. For broader coverage provision Trivy's
local database and select its isolated adapter. Never turn a missing database into
an empty successful result.
