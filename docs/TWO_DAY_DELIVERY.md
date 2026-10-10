# Two-day delivery target — 12 October 2026

Owner requested a two-day finish on 10 October, then explicitly chose blind
implementation with owner-run testing. The target is 12 October, Asia/Kolkata.
It is a delivery target, not a guarantee of production acceptance or a scheduled
background task. New implementation is UNVERIFIED until the owner tests it.

## 10–11 October: finish the reviewable build

- Close remaining release-blocking implementation defects without discretionary
  feature expansion. Shared source checks now prevent untracked/ignored inputs
  from entering both direct bundles and release packages.
- Finish three-mode configuration/handover, separate evidence locations and the
  owner test sheet. Do not execute scans/provider calls on the owner's behalf.
- Commit cohesive changes and prepare candidate builds; preserve normal CI policy,
  but do not dispatch, rerun or use new CI activity as owner acceptance.
- Keep experimental/unsupported capabilities and unresolved gates visible.

## 11–12 October: owner testing and delivery decision

- Owner exercises OWNER_TEST_SHEET.md with the prepared providers and target session.
- Owner/reviewer records actual findings, operating decisions and review outcomes.
- Developer fixes reported defects in implementation-only mode until testing is
  explicitly requested again; owner retests affected journeys.
- Select/freeze the final version and source only after predecessor acceptance.
  Final exact-commit evidence, stable packaging and publication still follow
  RELEASE_ACCEPTANCE.md with explicit release authorization.

If required evidence is incomplete on 12 October, deliver the candidate, source,
handover and exact blocker list. Do not relabel that delivery production-ready.
Owner statement that prerequisites are ready does not mean they have passed.
The currently mandatory local-AI gate remains unresolved by a testing deferral.
