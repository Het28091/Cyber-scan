# Secaudit development flow

Read `docs/PROJECT_STATUS.md` and `docs/FIVE_SPIRAL_PLAN.md` before development.
`docs/SCOPE.md` and `docs/FINAL_HANDOVER.md` define the owner-confirmed scope;
`docs/RELEASE_ACCEPTANCE.md` defines mandatory publication gates.
`docs/DEVELOPER_PROMPT.md` is the reusable execution prompt, not an automatic task.

- Start with the owner's requested phase; the next planned phase is Spiral 2.
  Do not start testing/deployment merely because a planning document mentions it.
  Explicit current user instructions override this repository guidance.
- Preserve existing changes. Work against the current spiral's task IDs, risks
  and acceptance criteria. Keep new discretionary features in a separate backlog.
- Keep implementation, verification and publication status separate. Historical
  passes and skipped CI do not validate current code. Never manufacture evidence.
- Use Linux for Linux runtime acceptance, owned fixtures for target actions and
  securely configured real providers for provider acceptance. Missing prerequisites
  remain blocked/NOT TESTED; do not weaken isolation or disclosure rules.
- When verification is authorized, run meaningful checks and record the actual
  result/commit/environment. Update status and capability/verification docs.
- No production-readiness claim or stable publication until required acceptance,
  operational exercises and owner sign-off are complete for the release commit.
  Never replace published tags or bypass exact-commit gates.
