# Secaudit technical assessment

Run: 037408c78db44255bda8ad8bd3371569

Mode: offline | State: COMPLETED_WITH_LIMITATIONS

Findings: 5



## Limitations

- Findings require manual validation; no compliance certification or complete vulnerability detection.

- Browser execution, state-changing active attacks, business-logic verification and authenticated role comparisons are not supported.

- Dependency matching is limited by supplied snapshots and inventory coverage; missing data remains NOT TESTED.

- Framework mappings are a reviewed subset of related evidence, not complete ASVS/NIST/ATT&CK control assessments.

- Source rules are syntax/regex heuristics; external scanners require a working isolated execution profile.



## Coverage

- source: PARTIAL — Bounded heuristic checks executed; manual validation required. Inventory records processed files.

- secrets: PARTIAL — Bounded heuristic checks executed; manual validation required. Inventory records processed files.

- config: PARTIAL — Bounded heuristic checks executed; manual validation required. Inventory records processed files.

- dependencies: NOT TESTED — DATA_MISSING: advisory snapshot absent

- openapi: PARTIAL — Bounded heuristic checks executed; manual validation required. Inventory records processed files.



## Dynamic code execution requires review

HIGH / MEDIUM / NEEDS MANUAL REVIEW

Location: app.py:6

Dynamic execution can interpret untrusted input. This is a syntax-based candidate, not data-flow proof.

Remediation: Remove dynamic evaluation or strictly validate trusted input.

Retest: Apply remediation and repeat this check; manually verify the affected workflow.



## Shell subprocess requires review

HIGH / MEDIUM / NEEDS MANUAL REVIEW

Location: app.py:8

shell=True enables shell interpretation.

Remediation: Use an argument list with shell=False.

Retest: Apply remediation and repeat this check; manually verify the affected workflow.



## Debug mode enabled

MEDIUM / MEDIUM / NEEDS MANUAL REVIEW

Location: app.py:3

Debug setting is enabled.

Remediation: Disable debug mode in production.

Retest: Apply remediation and repeat this check; manually verify the affected workflow.



## Potential hardcoded credential

HIGH / MEDIUM / NEEDS MANUAL REVIEW

Location: app.py:4

A credential-like assignment contains a literal. Value intentionally discarded.

Remediation: Review whether the value is sensitive; rotate exposed credentials and use a secret store.

Retest: Apply remediation and repeat this check; manually verify the affected workflow.



## API operation has no declared security

MEDIUM / MEDIUM / NEEDS MANUAL REVIEW

Location: openapi.json:1

GET /public has no non-empty security requirement; public endpoints may be intentional.

Remediation: Verify the intended authorization policy and document it.

Retest: Apply remediation and repeat this check; manually verify the affected workflow.



## AI usage

{"enabled": false, "provider": "none", "verified": "not used"}



## Framework snapshot

{"version": "secaudit-mappings-2026-09-22", "reviewed_at": "2026-09-22", "sha256": "18a063fcd3fce66667f6096f49cb5a006068eecbf9a21f2a31afa2094516729b", "sources": ["https://csrc.nist.gov/projects/cybersecurity-framework/filters", "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security/", "https://owasp.github.io/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"], "limitation": "Reviewed subset only; mappings are related evidence, not certification or control pass/fail."}



## Events

- dependency database: DATA_MISSING
