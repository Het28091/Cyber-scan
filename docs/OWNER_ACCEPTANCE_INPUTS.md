# Remaining owner inputs

Provider-independent development and Linux CI do not need the VM or an API key.
The next environment-dependent work is S2-04 live providers and the owner demo.
These inputs do not authorize publication or waive later release gates.

## VM and local Ollama

Start Kali and confirm its SSH address when ready for live provider/owner-machine
tests. Its checkout has not been synchronized since SSH became unavailable. The
developer must first preserve local changes, record the source/runtime and update
the checkout safely. Provide the exact installed Ollama model name and confirmed
host endpoint. No API key is needed for Ollama. Use the authenticated loopback
tunnel described in AI_QUICKSTART.md when Ollama runs on the host PC; do not expose
it publicly or change the local adapter's loopback policy.

## API provider

For live API acceptance, choose the provider, exact compatible HTTPS endpoint and
model. Privately configure `SECAUDIT_API_KEY` in the environment that will launch
the test. Do not paste the key into chat, JSON, Git or screenshots. Tell the
developer only the endpoint/model and credential variable name. A credential set
in another shell is not automatically visible to an existing service.

Confirm finding-metadata disclosure and permitted request/token/cost budgets.
The initial fixture contains owned synthetic findings. A free tier is not assumed:
no shared keys, account creation, guessed prices or paid calls without prepared
owner settings. Compatibility requires the application's model-listing and chat
protocol; a provider name alone does not establish compatibility.

After reviewing the configuration, the prepared Linux command is:

```bash
SECAUDIT_EXPERIMENTAL_AI=1 PYTHONPATH=. .venv/bin/python integration/ai_acceptance.py \
  --config /absolute/path/to/reviewed-provider.json \
  --evidence /absolute/path/to/private-provider-evidence.json
```

Use separate local/API configurations with `failure_policy=required`. Record exact
source, actual provider identity, readiness/inference/report results and relevant
failure/cancellation checks. Fixtures cannot replace these live results. Keep
secrets and private responses out of public evidence.

## Acceptance decisions

- Supply representative workloads and approve operating budgets on the intended
  hardware. CI timings are observations, not a throughput guarantee.
- Complete the dashboard demo: source and configured AI modes, profiles, review,
  refresh/download, retest comparison and backup/restore on a copy.
- Arrange independent security/quality review. Developer self-review is not
  independent sign-off.
- Agree evidence retention, support contact and launch observation period before
  Spiral 5. No automatic evidence deletion or support SLA is implied.

No further general permission question is necessary to continue already-authorized
tests once these inputs exist. Milestones remain unaccepted until their criteria
are met. Final release source/version, all ten exact-commit gates and explicit
owner release authorization are still required before publication.
