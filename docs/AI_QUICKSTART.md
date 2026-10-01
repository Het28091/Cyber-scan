# AI-assisted assessments

The local-model and API-provider adapters already exist. AI modes were hidden
unless the server environment enabled experimental AI. This implementation pass
makes both choices visible, adds startup flags and shows saved suggestions in the
dashboard. **This pass is unverified; no tests or debugging were run.**

## Enable the dashboard

After updating your Linux checkout, stop an existing dashboard with Ctrl+C and run:

```bash
bash run.sh dashboard --experimental-ai --output runs
```

Sign in with the newly printed session password. In **New assessment**, choose
**Local AI · Ollama** or **API AI · Compatible provider**. The flag enables AI for
that dashboard process and its scan jobs; it does not enable AI for non-AI scans,
download models or install a provider. The existing environment-variable opt-in
`SECAUDIT_EXPERIMENTAL_AI=1` remains supported. Without either opt-in, the modes
remain visible but disabled with startup instructions.

## Local AI

Use an Ollama runtime and model you have already prepared on the Linux machine.
Enter the exact installed model name. Default local transport settings are:

- Endpoint: `http://127.0.0.1:11434`
- Approved provider IP: `127.0.0.1`
- Request budget: 2 (readiness listing plus one inference request)
- Token budget: 8192; request timeout: 15 seconds

Increase the timeout if your prepared model needs more time, up to the supported
120-second limit. The configured model must appear in the provider's model listing.
Only loopback addresses are allowed for local AI. No API credential is used by
the Ollama adapter.

### Kali VM with Ollama on its host

The VM's `127.0.0.1` refers to the VM, not its host. Keep the local-provider
loopback policy: use an authenticated SSH tunnel instead of exposing Ollama on
all network interfaces or allowing LAN addresses in the adapter.

If SSH access to Kali is already configured, run this from the host PC, replacing
the uppercase placeholders with the owner's verified connection details:

```text
ssh -N -o ExitOnForwardFailure=yes -R 127.0.0.1:11435:127.0.0.1:11434 -p KALI_SSH_PORT KALI_USER@KALI_ADDRESS
```

This assumes the host's prepared Ollama actually listens on `127.0.0.1:11434`;
adjust that destination only to its confirmed local endpoint. Verify the SSH host
key, keep the tunnel terminal open, and use `http://127.0.0.1:11435` with approved
IP `127.0.0.1` in Kali's Secaudit form. Use the exact installed model name and
explicitly approve finding-metadata disclosure. If the forward cannot bind, stop
and choose an unused loopback port. Do not change SSH GatewayPorts or disable
host-key checking. Closing the SSH connection removes this temporary forward.

This is preparation guidance, not evidence of successful provider acceptance.
Spiral 2 still requires real model readiness, inference and saved-report evidence.

## API AI

Use your configured provider's HTTPS API base URL, advertised model name and
reviewed literal IP pins. The adapter requires compatible `/models` and
`/chat/completions` endpoints; compatibility is not implied for every provider.
Keep credentials in a server environment variable, never in JSON or chat.

For example, enter a key privately in a Bash terminal before starting the dashboard:

```bash
read -r -s -p 'API key: ' SECAUDIT_API_KEY
printf '\n'
export SECAUDIT_API_KEY
bash run.sh dashboard --experimental-ai --output runs
```

In the provider form, use `SECAUDIT_API_KEY` as the credential variable name.
The already-running dashboard cannot read environment changes in another terminal;
restart it from the environment containing the credential. Changed DNS addresses
require reviewing and updating the approved IP pins.

## Run and review

Start with source `demo/source`, no target and no optional scanners. Select an AI
mode, configure the provider, accept the finding-metadata disclosure and assessment
authorization, and submit. New dashboard AI configurations default to **Require AI
readiness**, so unavailable providers block preflight. You may explicitly choose
**Continue without AI**; existing profiles retain their stored policy.

Open **Reports & evidence** for the completed run. The AI assistance section shows
provider/model, readiness, recorded inference status, usage and suggestions linked
to finding details. Suggestions are also downloadable as JSON when saved. If
there are no findings, no inference is performed. An empty suggestions list does
not establish success; review run events and coverage.

Current AI functionality is metadata-based remediation assistance for at most ten
existing findings. Only IDs, rule identifiers and severity are disclosed. Source,
paths, observations and credentials are not part of the inference payload. Output
is untrusted text and does not confirm vulnerabilities, change operator decisions
or execute commands. There is no autonomous AI scanner or source-code chat.

For the CLI, edit the supplied configuration with your actual provider settings:

```bash
bash run.sh scan --experimental-ai --config config/local-ai.json --output runs
# Or, with the credential environment prepared:
bash run.sh scan --experimental-ai --config config/api-ai.json --output runs
```

`doctor` also accepts `--experimental-ai`. Placeholder model names and API pins in
the supplied configuration files must be replaced. Real local/API-provider
acceptance, including cancellation and failure cases, remains pending.
