# Expanded release evidence gate

Updated 30 September 2026. This gate is implemented; expanded release acceptance
has **not** passed. Historical v1.1.0 results do not satisfy it.

Candidate packages remain available for testing. Packaging now requires the supplied
full commit SHA to match HEAD and every bundled source input to be committed. Build
checks also reject linked source inputs and ignored files inside bundled directories, except excluded
Python bytecode/cache files, so an ignored credential file cannot silently enter a
versioned package. Stable packages additionally require `--acceptance-manifest`.
Stable asset collection requires
`SECAUDIT_ACCEPTANCE_MANIFEST` (default `artifacts/acceptance/manifest.json`). There is
no skip/bypass option. No tag, version or release was created by this change.

Acceptance records must be generated **after** the source commit and supplied outside
its tracked source tree, for example as a trusted CI artifact. Do not commit records
that claim to describe the commit containing themselves. A new source commit needs
new acceptance records. Keep private source, credentials and raw sensitive reports
out of distributable evidence.

## Required records

The manifest must contain every gate below, each with its own JSON record. Every
record must match the exact source commit and application version. PASS, completed
checks and explicitly empty `unresolved_requirements` are mandatory. NOT TESTED,
SKIP, FAIL, missing gates, fixture provenance, changed files and stale versions fail.

| Gate | Required kind | Additional evidence fields |
|---|---|---|
| `original_brief` | `operator-attestation` | `reviewer`; reconciled requirement coverage in checks |
| `non_ai` | `linux-acceptance` | `platform: Linux`, `modes_verified: [offline, internet]` |
| `local_ai` | `real-provider` | `mode: local-ai`, `real_provider_verified: true`, `provider_identity` |
| `api_ai` | `real-provider` | `mode: connected-ai`, `real_provider_verified: true`, `provider_identity` |
| `dashboard` | `browser-acceptance` | `platform: Linux` |
| `target_workflows` | `linux-acceptance` | `platform: Linux` |
| `target_browser` | `browser-acceptance` | `platform: Linux` |
| `detection_frameworks` | `operator-attestation` | `reviewer`; required coverage and explicit unsupported cases reconciled |
| `owner_machine` | `operator-attestation` | `reviewer`; completed owner-machine checklist |
| `linux_ci` | `ci-acceptance` | `platform: Linux`, `conclusion: success`, GitHub Actions `run_url` |

Manifest shape (all ten gates are required; this deliberately incomplete example
cannot pass):

```json
{
  "schema": 1,
  "source_commit": "FULL_40_CHARACTER_COMMIT",
  "app_version": "VERSION_UNDER_TEST",
  "gates": {
    "local_ai": {
      "status": "NOT TESTED",
      "evidence": "local-ai.json",
      "sha256": "SHA256_OF_EXACT_RECORD_BYTES"
    }
  }
}
```

Each record has `gate`, `status`, `kind`, `source_commit`, `app_version`, a nonempty
list of named `checks`, and `unresolved_requirements`, plus the fields above. Only
an operator with actual verification evidence should record PASS and attest to a
real provider. Acceptance-script outputs are supporting evidence, not automatically
approved envelopes: review their limitations and identify the actual runtime first.
Do not relabel a protocol fixture as a real provider run.

The validator checks local record structure, declared provenance, versions, paths and
SHA-256 integrity. It does **not** authenticate an unsigned attestation, contact a CI
URL to verify its conclusion, or detect a dishonest report. Use trusted operator/CI
provenance and retain the actual logs and outputs for review. The same manifest digest
must be attached to every stable bundle and supplied to collection.

## Commands

```sh
python -m secaudit release-check --manifest /prepared/acceptance/manifest.json \
  --commit FULL_SOURCE_COMMIT

PYTHONPATH=. python scripts/package-release.py --commit FULL_SOURCE_COMMIT \
  --output artifacts/candidate --with-wheels --channel candidate

PYTHONPATH=. python scripts/package-release.py --commit FULL_SOURCE_COMMIT \
  --output artifacts/stable --with-wheels --channel stable \
  --acceptance-manifest /prepared/acceptance/manifest.json

GITHUB_SHA=FULL_SOURCE_COMMIT PYTHONPATH=. \
SECAUDIT_ACCEPTANCE_MANIFEST=/prepared/acceptance/manifest.json \
  python scripts/collect-release.py
```

Packaging with `--with-wheels` is explicit connected preparation. Collection expects
the four supported stable Linux/Python bundles under `incoming/`. It verifies complete
outer checksums, exact manifest membership, unique regular archive files and resource
bounds before creating final assets. Missing checksums, unexpected files, archive
links, duplicate entries and path traversal are rejected. Failed collection leaves
no partial `release-assets` directory. Successful collection includes the gate summary
in the final checksums.

## First-round publication integration

The old v1.1 commit-message publishing job is removed. Ordinary CI runs build
candidate packages only. The acceptance workflow also supports manual dispatch
for the later verification round. No CI was dispatched as part of this handover.

Choose an unused final numeric application version **before** the final source
commit and its acceptance runs. The current 1.1.0 tag already exists and cannot
be replaced. Do not bump the version after gathering evidence: that would require
new exact-commit acceptance. Prepare reviewed release notes for that version.

After committing the final source, initialize outside the bundled source paths:

```sh
PYTHONPATH=. python scripts/acceptance-records.py init --commit FULL_SOURCE_COMMIT \
  --directory artifacts/acceptance-final
```

This creates ten **NOT TESTED** records with unresolved requirements. Perform the
actual acceptance, retain supporting logs and fill the records truthfully. The
`original_brief` gate name is retained for schema compatibility; for round one its
operator review covers the owner-confirmed SCOPE.md and FINAL_HANDOVER.md matrix.
No separate master brief is required for that confirmed round-one boundary.

After review, seal the exact record bytes and run the existing validator:

```sh
PYTHONPATH=. python scripts/acceptance-records.py seal --commit FULL_SOURCE_COMMIT \
  --directory artifacts/acceptance-final
python -m secaudit release-check --manifest artifacts/acceptance-final/manifest.json \
  --commit FULL_SOURCE_COMMIT
```

Sealing preserves statuses and does not convert NOT TESTED/FAIL into PASS. It
refuses an existing manifest. For a new commit or revised record set, use a new
directory and retain the previous evidence history.

Build stable bundles on Linux x86_64 using the same source commit, manifest and
Python 3.11, 3.12, 3.13 and 3.14 environments. For each environment, use the earlier
`package-release.py --channel stable --with-wheels --acceptance-manifest ...`
command with a distinct new output directory. Copy each resulting directory into
`incoming/python3.11/`, `incoming/python3.12/`, `incoming/python3.13/` and
`incoming/python3.14/` on the publishing checkout. Candidate bundles cannot be
relabeled stable: their metadata will be rejected.

The GitHub CLI must be installed/authenticated. From the repository root:

```sh
PYTHONPATH=. python scripts/publish-release.py \
  --commit FULL_SOURCE_COMMIT \
  --manifest artifacts/acceptance-final/manifest.json \
  --repository Het28091/Cyber-scan --ci-run SUCCESSFUL_CI_RUN_ID \
  --notes /path/to/reviewed-release-notes.md
```

Without `--publish`, this checks and collects local `release-assets/` only. It
reads GitHub to verify that the exact repository commit passed the actual
`.github/workflows/test.yml` workflow and all fourteen mandatory jobs in the same
run attempt. A skipped workflow, pull-request run, wrong SHA, missing job, failed
job or mismatched evidence URL is rejected. It also refuses an existing version
tag. The private raw assessment reports are not required as publication assets;
only the reviewed, distributable acceptance envelopes are included.

For publication, invoke the same command with `--publish` from a checkout where
`release-assets/` does not already exist. If you previously prepared it, move that
directory aside for review first. The command rechecks all gates, assembles the
assets, creates a draft release with the exact commit and then publishes it.
It never replaces an existing tag/release. If the final publish call fails, the
draft may remain and requires operator inspection; the script will not silently
overwrite it on retry.

Assets include four stable bundles, source archive, metadata, exact acceptance
record bytes in `acceptance-records.zip`, actual CI verification and checksums.
Hashes check integrity, not whether a human attestation is truthful. This new
publisher/scaffolding code is **UNVERIFIED**; its runtime verification belongs to
round two. No release or PASS record was created during implementation.
