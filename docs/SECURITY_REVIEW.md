# Adversarial review — 0.4.1

Reviewed 2026-09-22 against the Linux non-AI pipeline. This is a source review and
regression-testing pass, not an independent penetration-test certification or proof
that all possible edge cases are covered. All attack-shaped inputs were exercised
against synthetic local fixtures or isolated temporary directories.

## Trust boundaries reviewed

Authorized operator configuration; untrusted source/ZIP/HTTP content; loopback
HTTP dashboard; subprocess and AI boundaries; advisory data; stored evidence;
recovery; setup/bundle commands; and documentation claims. The prior 0.4 GitHub CI
run completed successfully, but the old suite did not cover the issues below.

## Findings and fixes

| Finding | Consequence before fix | Fix / regression evidence |
|---|---|---|
| Ambiguous URL paths and port zero | `:0` silently selected the default port; semicolon variants could evade exclusions on servers that normalize path parameters | Reject port zero, semicolon/encoded delimiter paths, invalid UTF-8 and DEL before DNS; exclusions tested |
| Malformed scope types | Arrays/non-string lists could raise an unexpected exception | Validate object, list, scalar and allowed-field shapes; clean policy failures |
| Rejected job artifacts | Upload/config files could be left behind after validation or queue rejection | Validate and reserve capacity first; rollback created files on failure |
| Competing dashboard instances | A second dashboard using the same output directory could mark the first one's jobs interrupted | Exclusive Linux file lock; second instance refused before recovery |
| Overbroad recovery | Resuming one run could mark unrelated RUNNING records interrupted | Recover only the selected run; require a canonical run ID |
| Malformed dashboard requests | Duplicate length headers, non-ASCII auth and deeply nested JSON were not robustly handled | Reject ambiguous headers/incomplete bodies; safe auth comparison and parser error responses |
| Unbounded HTTP worker threads | Many local connections could allocate unbounded workers | Cap concurrent connections at eight; socket inactivity timeout remains 15 seconds |
| Corrupt stored history | Wrong-shaped JSON could break history/detail requests | Validate history/run shapes and return controlled errors |
| Malformed target links/redirects | Invalid URL syntax could abort a crawl | Skip blocked/malformed links and redirects without losing earlier observations |
| Broken HTTP preflight | Invalid target protocol responses could escape the expected error path | Report UNREACHABLE and block the assessment |
| Invalid advisory snapshot publication | Invalid input could overwrite/publish dataset files before validation | Validate staged data first; refuse an existing versioned destination |
| Strict scanner failure / evidence gaps | A required dataset runtime failure could be swallowed; successful external findings could be lost on a later failure | Fail required checks; checkpoint completed module findings |

No exploitability-based CVSS score is assigned to these findings. The consequences
above describe tested behavior or, for server-specific URL normalization, a potential
interaction that the scanner now rejects conservatively.

## Test coverage

77 tests passed using `bash run.sh test`. The new `tests/test_hardening.py` covers
26 additional regressions beyond the prior 51-test suite. It includes raw HTTP
requests against the local dashboard and subprocess CLI tests. Existing tests also
cover redirect scope, DNS rebinding, source network denial, archive traversal and
symlinks, expansion limits, CSV injection, HTML escaping, redaction, AI policy,
offline bundles, PDF generation, provider failures and scanner time/output limits.

`make doctor`, `make demo` and JavaScript syntax checks passed. The demo produced
five expected source candidates. Local Markdown links were checked and resolved.
An initial offline setup attempt failed because this restored workspace contained
corrupt pip bytecode (`EOFError: marshal data too short`). Removing only pip's
generated `.pyc` cache and rerunning the same offline setup succeeded. This was an
environment repair; no project source, evidence or dependency versions were changed.

## Documentation corrections

The architecture now distinguishes source-only network denial from internet-mode
advisory access. Dataset documentation states that snapshot filenames must be new.
Recovery documentation states that only the selected stopped run is recovered.
The README documents conservative URL rejection and single-dashboard ownership.
Historical demo reports are identified as 0.3 examples, not 0.4.1 verification.

## Residual risks and unverified areas

- No successful live OSV query or externally hosted authorized target test here.
- Browser-level UI interaction and accessibility testing remain outstanding; HTTP
  endpoint tests and JS syntax checks do not replace those checks.
- External scanner binaries and real AI providers remain fixture-tested, not fully
  verified. Full browser, active and role-comparison scanning is not implemented.
- Reverse proxies and application routers can normalize paths differently. The
  conservative URL rules reduce ambiguity but do not prove equivalence with every
  server. Test deployment-specific routing before trusting exclusions.
- Output directories and configuration are operator-controlled. An attacker with the
  same OS account can tamper with files or credentials; this is not a multi-user
  security boundary. Keep input trees immutable during scanning.
- The loopback server is not hardened for public hosting. Eight connections and socket
  inactivity timeouts bound some resources, but do not eliminate local denial of
  service or slow trickle requests. Do not expose it to a network.
- SIGKILL, power failure and disk exhaustion can interrupt output generation. Atomic
  single-file writes and checkpoints do not form a transaction across every artifact.
- Built-in detection is heuristic. Missing findings, partial inventories, advisory
  gaps, unrecognized secrets and false positives remain possible.

Further work should add browser acceptance, live provider/tool verification and
additional protocol/property-based tests. This review must not be described as
“all edge cases covered,” “perfect,” or “production security certified.”
