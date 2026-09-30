# Developer execution prompt

Copy the prompt below into the developer's next task to start Spiral 2. Replace
the phase only when its predecessor's acceptance is recorded. This file does not
start execution by itself. The project owner's current instructions take priority.

```text
Act as the implementation lead for Secaudit. Continue from the existing repository;
do not rebuild the application or restart the first spiral.

Read AGENTS.md, docs/PROJECT_STATUS.md, docs/FIVE_SPIRAL_PLAN.md,
docs/SCOPE.md, docs/FINAL_HANDOVER.md and docs/RELEASE_ACCEPTANCE.md.
Use docs/ROUND_ONE_HANDOVER.md and the implementation ledger for code traceability.
The owner confirmed SCOPE.md and FINAL_HANDOVER.md as the complete first-round scope.

Objective: execute Spiral 2, starting with S2-01, and deliver the verified milestone.
For this execution, testing and debugging are required: the earlier no-testing
approach was the prototype pass. Do not treat historical tests or [skip ci] commits
as current verification. Do not claim production readiness at the end of Spiral 2.

1. Inspect working-tree/branch state and preserve existing changes. Record the
   baseline commit and runtime. Identify a usable Linux environment, prepared
   provider/tool availability and missing inputs. Never ask for credentials in chat.
2. Establish the current setup/test baseline before broad feature work. Run checks
   on the supported platform. Record exact failures and distinguish unsupported
   host/tool/provider conditions from product defects. Never disable a safety
   boundary just to get a test or scanner running.
3. Execute S2-01 through S2-05 by risk and dependency. Make focused fixes with
   regression coverage. No unrelated feature expansion or cosmetic redesign.
   Use owned fixtures for target traffic. Real provider calls must use the owner's
   configured endpoint/model, environment credential and approved disclosure;
   do not incur charges or contact unrelated services on guessed settings.
4. Verify changes with relevant targeted checks, then the milestone's required
   suite and real browser/provider acceptance. Preserve isolation, scope pins,
   non-AI independence, redaction, immutable scanner evidence and review revisions.
   A fixture result never substitutes for required real-provider/browser evidence.
5. If an environment-dependent task is blocked, record the exact missing input,
   responsible role and next action. Continue independent authorized work. Do not
   label the blocked requirement done or remove it from the scope.
6. Update docs/PROJECT_STATUS.md, the backlog state in docs/FIVE_SPIRAL_PLAN.md,
   relevant capability docs and docs/VERIFICATION.md with source commit, task IDs,
   checks actually run, evidence paths and residual risks. Keep implementation and
   verification status separate; do not fabricate completion percentages.
7. Commit cohesive changes using repository conventions. Push when authorized by
   the owner/current workflow. Verification commits must run the intended CI;
   never use [skip ci] as evidence for a verified milestone. Do not tag, publish,
   force-push or replace an existing release as part of Spiral 2.
8. Continue until Spiral 2's exit criteria are met or a concrete external blocker
   prevents further useful work. Report milestone status, open P0/P1 defects,
   evidence, owner inputs and the next task. Do not silently proceed to production.

Production target: Linux x86_64 local single-operator assessment application with
Python 3.11–3.14, independently usable offline/internet modes and optional local/API
AI. Current browser behavior is isolated static snapshots; AI is metadata-based
remediation assistance. Do not imply autonomous exploitation, full interactive
browser scanning, multi-user SaaS or compliance certification.

Before a later release: complete Spirals 3–4, then Spiral 5 owner acceptance and all
ten exact-commit gates. Obtain release authorization and use the gated publisher.
If any required check is FAIL, SKIP, NOT TESTED or stale, do not publish.
```

For subsequent spirals, change the objective to the selected spiral and its task
IDs, apply that spiral's entry/exit criteria, and retain the evidence/scope rules.
The prompt deliberately authorizes testing for its future execution; this PM
planning task has not executed it or withdrawn any still-active user restriction.
