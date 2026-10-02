# Expanded local application threat model

Review scope: S3-01/02/05, provider-independent code and owned fixtures. This is a
developer review, not an independent security assessment or certification.

Trusted: the single operator, selected configuration, immutable checkout and owned
output directory. Untrusted: source archives, scanned text, target responses,
provider/scanner outputs and imported artifacts. A hostile process under the same
OS account can rewrite evidence/configuration; local file checks do not isolate
that account. The dashboard is not a public or multi-user service.

| Boundary / abuse case | Control / implementation | Existing evidence / limits |
| --- | --- | --- |
| Target escapes authorization via redirects, path encoding or DNS rebinding | `Scope`, canonical URL rejection and connection-time IP pins in `security.py`/`network.py` | `test_security`, `test_auth`, `test_hardening`, `test_review`; deployment router equivalence remains operator-specific |
| Website drives local dashboard actions | Loopback bind, Host validation, Basic session password, Origin and CSRF for mutations | Raw HTTP negative tests plus real browser owned journeys; no public hosting claim |
| ZIP traverses output paths or source invokes code | Bounded extraction, no links, source parsed rather than imported; subprocess source isolation | Archive/input and seccomp regressions; operator keeps input tree immutable |
| Scanner reads host secrets or phones home | Bubblewrap read-only mounts, cleared environment, network namespace, bounded process group | Actual Gitleaks/Semgrep/Syft/Trivy jobs; no unsandboxed fallback |
| Static Chromium runs scripts/subresources | Pinned single HTML fetch then isolated offline render; script disable before navigation; verified cgroup memory/swap/task limits; Chromium sandbox retained | Real Kali and CI acceptance PASS at `250e82e`, including oversized allocation, static form and no script/subresource request controls; see INDEPENDENT_EXECUTION.md |
| Provider sees private source or injects instructions | Allowlisted finding ID/rule/severity payload, experimental opt-in and disclosure, validated inert text | Protocol/schema/non-AI independence tests; actual provider credentials and inference still absent |
| Credentials appear in artifacts | Registered-secret and pattern redaction, discarded scanner matches, environment references | Existing canary/redaction tests; arbitrary operator-authored text is not guaranteed secret-free |
| Report refresh exposes a mixture of generations | Staging, INCOMPLETE/READY record, content digests and read-time generation check | New failure-injection regressions; legacy records are not upgraded merely by reading them |
| Restore replaces live evidence or escapes destination | New destination only, local-tree-derived paths, no symbolic links, manifest equality | Backup/restore regression corpus; snapshots are not signed or encrypted |
| New state is opened by older software | Future schema guard before mutation; rollback uses pre-upgrade data copy | Future-version regressions; operational old-release exercise records its exact source |

Remaining risk register:

- **Resolved P1 at `250e82e`:** renderer startup now passes on Kali and CI with
  kernel-verified physical-memory containment and separate bounded internal-file
  and output budgets. Missing cgroup/user-manager support still fails closed;
  no `--no-sandbox`, host policy override or unlimited run is permitted. This
  developer verification does not replace independent security review.
- **Blocked evidence:** actual AI provider calls, owner UAT, independent security
  review and owner-approved workload budgets are missing. CI fixtures cannot waive them.
- **Operational limit:** backups require all writers stopped; report publication
  detects interruption but does not promise power-loss atomicity across a directory.
- **Detection limit:** syntax/declaration and adapter results are candidates for
  manual validation. Corpus counts are dataset-specific, with partial framework
  associations. No complete vulnerability or compliance assurance is claimed.

Any future exception needs a named owner, rationale and review date. None of these
notes waives a mandatory release gate or constitutes owner risk acceptance.
