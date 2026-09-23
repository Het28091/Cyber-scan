# Scanner and AI adapter contracts

## External source scanners

The optional adapters accept a read-only source directory and return normalized
Finding objects or CycloneDX. Select tools in `modules` and configure `scanners`:

```json
{
  "source": "demo/source",
  "modules": ["source", "gitleaks", "semgrep", "trivy", "syft"],
  "scanners": {
    "gitleaks": {"executable": "/usr/local/bin/gitleaks"},
    "semgrep": {"executable": "/usr/local/bin/semgrep", "rules": "/absolute/path/rules.yaml"},
    "trivy": {"executable": "/usr/local/bin/trivy", "cache": "/absolute/path/trivy-cache"},
    "syft": {"executable": "/usr/local/bin/syft"}
  }
}
```

Install operator-reviewed releases using each project's official distribution
instructions on a connected preparation machine. Preserve release checksums/signatures,
licenses, local rules and databases. Install Bubblewrap through your distribution.
Do not pipe unreviewed remote installers into a shell. Scanner installation and
updates are intentionally not performed by assessment or preflight.

| Adapter | Accepted version family* | Input / output | Offline controls |
|---|---|---|---|
| Gitleaks | 8.x | `dir /input`; redacted JSON | No Git/network mode, raw matches discarded |
| Semgrep | 1.x | Local rule file; JSON | Metrics/version checks off; no registry rules |
| Trivy | 0.x | Filesystem plus local DB; JSON | Updates and version checks off; offline scan; memory scan cache |
| Syft | 1.x | Local directory; CycloneDX JSON | Update checks off; no image registry input |

*These are parser gates, **not claims that every release is compatible**. Gitleaks
8.24.2 is live-verified in Bubblewrap. Semgrep 1.175.0 acceptance is in progress;
Trivy and Syft remain fixture-tested. Use a tested pinned release and record its
version. A tool that cannot start or returns malformed output never produces a
clean result.

Every launch requires a successful Bubblewrap probe. The sandbox unshares namespaces,
clears the environment, drops capabilities, supplies temporary HOME, mounts tools
and input read-only, and does not expose the operator's home or Docker socket.
The working directory is `/tmp`, so tool auto-discovery does not load project-root
configuration by default. Processes have time, output, file-size, open-file and
address-space bounds. Timeout/cancellation terminates the process group. Raw stderr
is discarded. Tool distribution dependencies must be visible in the sandbox; a
standalone executable may need bundled support files. Trivy's database is read-only.

ZAP, testssl.sh and browser automation are not implemented: they require an additional
reviewed network execution profile. No unconstrained scanner runs as a fallback.

Official adapter references reviewed 2026-09-22:

- https://github.com/gitleaks/gitleaks
- https://docs.semgrep.dev/cli-reference
- https://docs.semgrep.dev/metrics
- https://trivy.dev/docs/v0.56/guide/advanced/air-gap/
- https://www.trivy.dev/docs/latest/guide/references/configuration/cli/trivy_filesystem/
- https://oss.anchore.com/docs/reference/syft/configuration/

## AI boundary

Experimental only: both configuration validation and Provider construction require
`SECAUDIT_EXPERIMENTAL_AI=1`. This does not enable AI in offline/internet modes.

`Provider.health()` verifies the model is advertised. `Provider.suggest()` accepts
normalized finding metadata and returns `{suggestions: [{id, text}]}`. Future
adapters must retain endpoint/IP checks, budgets, environment credential handling,
redaction and schema validation. No arbitrary plugin loading from scanned projects.

Ollama: GET `/api/tags`, POST `/api/chat`, loopback only, preinstalled model.
OpenAI-compatible: GET `/models`, POST `/chat/completions`, HTTPS and explicit IP pins.
No tools, streaming or provider-specific JSON mode is assumed. Retry limit is zero;
concurrency is one. Stub verification is distinct from a real-provider smoke test.

## Framework snapshot

`secaudit/data/frameworks.json` contains original mapping rationale and selected
identifiers, with source URLs and a review date. Each run records its SHA-256 and
version. NIST CSF ID.RA-01 is evidence context; WSTG references cover HSTS/cookie
observations. No control is declared passed by this mapping. This is a small subset,
not a full standards corpus or organizational audit. No proprietary standards are
redistributed; ATT&CK is not a sequential testing workflow.

## Gitleaks runtime memory acceptance

Live testing of Gitleaks 8.24.2 exposed a startup panic under the generic 2 GiB
virtual-address limit: its WASM regex runtime reserves 4 GiB before scanning.
Gitleaks now has a finite 8 GiB RLIMIT_AS ceiling; other adapters retain 2 GiB.
This limit measures virtual address space, not resident memory. It is not a cgroup
RSS limit. CPU/time, output/file/descriptor limits and mandatory Bubblewrap
network/input/environment/capability isolation remain enforced.

Gitleaks reports use the upstream stdout sentinel `--report-path -`. `/dev/stdout`
is not equivalent: report initialization may unlink/recreate that path in the
sandbox, causing JSON to be written to a file rather than the captured pipe.
The live positive and clean controls exercise the actual stream/parser boundary.

## Semgrep startup trust bundle

Real Semgrep 1.175.0 initializes its TLS library even for `--version` and aborts
without a CA bundle. Its adapter mounts one system public CA certificate bundle
read-only at `/etc/ssl/certs/ca-certificates.crt`. It does not expose the rest of
`/etc`, private keys or user configuration. Missing bundles fail preflight.
Network namespaces, dropped capabilities, cleared credentials and resource limits
remain mandatory; availability of trust anchors does not enable network access.
