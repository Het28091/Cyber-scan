# Declaration checks — feature-first implementation

Added 30 September 2026. **UNVERIFIED:** tests and debugging are deferred under
the owner's spiral-development direction. This is an implementation catalogue,
not evidence that the rules detect every listed condition correctly.

The existing `openapi` and `config` modules run these checks when traversing JSON
source files. No extra scanner installation, network access, reference fetching,
manifest execution or cluster credentials are required. Existing traversal limits
apply. Findings use the filename and JSON pointer rather than fabricated line
numbers; source values are omitted from evidence. They appear in normal findings,
reports and the remediation work list, with manual review required.

## OpenAPI JSON (`openapi` module)

| Rule | Declaration inspected |
| --- | --- |
| `API-SECURITY` | Operation/root security is absent, empty, or contains an anonymous `{}` alternative |
| `API-SECURITY-REFERENCE` | Operation security names a scheme absent from local `components.securitySchemes` |
| `API-CLEARTEXT-SERVER` | Root, path or operation server URL explicitly starts with `http://` |
| `API-QUERY-CREDENTIAL` | An API-key security scheme declares `in: query` |
| `API-OAUTH-FLOW` | An OAuth2 security scheme declares an implicit or password flow |

An operation's security declaration overrides root security. Public operations and
local HTTP servers can be intentional. Scheme references are not resolved, so an
absent local definition needs reconciliation rather than automatic confirmation.
The existing `API-SECURITY` finding wording/fingerprint changes in this pass; old
and new findings may appear as possibly moved during saved-run comparison.

This is not an OpenAPI schema validator. YAML, Swagger 2, links, callbacks, webhooks,
reference resolution, server-template expansion, OAuth provider behavior and actual
runtime enforcement are not covered. Reference inventory is bounded at 20,000
container nodes and records a limitation if that bound is reached.

## Kubernetes JSON (`config` module)

Supported workload shapes: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
ReplicationController, Job and CronJob, either directly or in a `kind: List`
document. List inspection is capped at 1,000 objects, with a limitation event for
remaining objects. Container checks include regular, init and ephemeral containers.

| Rule | Explicit declaration inspected |
| --- | --- |
| `K8S-HOST-NAMESPACE` | `hostNetwork`, `hostPID` or `hostIPC` is true |
| `K8S-TOKEN-MOUNT` | `automountServiceAccountToken` is true |
| `K8S-HOST-PATH` | A volume declares a `hostPath` object |
| `K8S-PRIVILEGED` | Container `privileged` is true |
| `K8S-ESCALATION` | Container `allowPrivilegeEscalation` is true |
| `K8S-ROOT` | Container or inherited pod `runAsUser` is explicitly zero |
| `K8S-CAPABILITIES` | Added capabilities include ALL, SYS_ADMIN, SYS_PTRACE or NET_ADMIN |

Omitted settings do not produce these findings. Defaults, images, admission
controllers, node policies, service-account permissions and runtime overrides are
unknown. No YAML parser, Helm/Kustomize renderer, cluster connection, RBAC analyzer
or general infrastructure-as-code engine is included in this pass.

These rules receive the existing generic related-evidence NIST mapping. No new
rule-specific framework mapping or compliance result is claimed.
