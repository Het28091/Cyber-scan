# v1.0 release acceptance

Status: **not released**. Feature development remains frozen. This checklist defines
completion of the existing Linux governance/orchestration workflow, not exhaustive
vulnerability detection or certification.

## Required gates

- [x] Live, bounded OSV lookup and real Bubblewrap/Gitleaks positive/negative controls.
- [x] Static authenticated GET/HEAD with scoped credentials and negative boundary tests.
- [x] More than 80% measured statement coverage, including subprocess execution.
- [x] Ubuntu 22.04 and 24.04, Python 3.11–3.14 clean and repeat setup.
- [x] Matching wheel bundles install with seccomp network denial; installed CLI produces
  findings, PDFs and CycloneDX output from paths containing spaces and a different cwd.
- [x] Complete real-browser acceptance, including report downloads, failed jobs and cancellation.
- [ ] Review desktop/mobile screenshots and accessibility (contrast, keyboard, accessible names).
- [x] Record a green acceptance commit and durable [evidence](evidence/v1-acceptance.json).
- [ ] Keep the final versioned release candidate green.
- [ ] Create versioned release archives, checksums and migration/release notes; publish a tag/release.

Acceptance evidence: [Actions run 35815308853](https://github.com/Het28091/Cyber-scan/actions/runs/35815308853),
commit `9d58fd714e1ca93718a72b0c30fd3d3b32659756`. All eleven jobs passed, including
eight distribution combinations, real Chromium, live integrations and security/coverage gates.
Desktop/mobile screenshots were reviewed. Contrast/small-text accessibility remains a UI follow-up. The stale submission notice
found in screenshot review has been fixed; its browser assertion passed in [run 35815527454](https://github.com/Het28091/Cyber-scan/actions/runs/35815527454).

## Migration and artifact requirements

Preserve existing `runs/` evidence. Stop the dashboard before updating its checkout,
rerun `bash setup.sh`, then launch with `bash run.sh dashboard`. No stored token
migration is needed: static target credentials remain environment references.

A wheel bundle must match the destination Linux architecture and Python minor version.
The tested matrix is Linux x86_64 on the Ubuntu versions above; it does not establish
acceptance on every distribution, ARM64 or Windows. Bubblewrap policy and libseccomp
are mandatory for their respective isolation paths; never disable host security policy
to make a failed prerequisite appear ready.

Release archives must identify their source commit, version, tested platform and
Python minor version. SHA-256 manifests detect corruption, not publisher authenticity;
bundles remain unsigned. CI evidence artifacts expire after 14 days and must not be
the only durable release record.

## Explicit limits

Browser acceptance means testing the local dashboard; it does not add browser-based
scanning of target applications. Login automation, role comparison, active exploitation,
new detection engines and AI-provider support remain outside this milestone. Semgrep,
Trivy and Syft are not yet live-verified. An externally hosted authorized target test
also remains outstanding; local owned fixtures and live OSV are not substitutes for it.


## Candidate archives

Each distribution job builds an explicitly marked candidate archive with locked wheels,
`release.json` source-commit metadata and `SHA256SUMS`. Download the artifact matching
your tested Ubuntu/Python combination from the successful CI run. These expire after
14 days and are not a stable GitHub release. Keep the metadata and checksums alongside
the archive. After downloading, verify before extracting:

```bash
sha256sum --check SHA256SUMS
```

The archive contains a bundle directory usable with the documented `bundle verify`
and `bundle install` commands. System Python/venv and libseccomp must already be
available; the bundle does not provision system packages offline. Use the same Python
minor version as the candidate metadata. The final stable release still requires the
remaining acceptance gates and publication.
