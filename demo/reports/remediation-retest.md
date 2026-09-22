# Remediation and retest plan

- 5039eab36f64cdbd (HIGH): Remove dynamic evaluation or strictly validate trusted input. Retest: Apply remediation and repeat this check; manually verify the affected workflow.

- eeb5dcc6ff35659b (HIGH): Use an argument list with shell=False. Retest: Apply remediation and repeat this check; manually verify the affected workflow.

- 9f3f1e34e14cad93 (MEDIUM): Disable debug mode in production. Retest: Apply remediation and repeat this check; manually verify the affected workflow.

- 873be20af1527489 (HIGH): Review whether the value is sensitive; rotate exposed credentials and use a secret store. Retest: Apply remediation and repeat this check; manually verify the affected workflow.

- f6fcf34abb6944b0 (MEDIUM): Verify the intended authorization policy and document it. Retest: Apply remediation and repeat this check; manually verify the affected workflow.