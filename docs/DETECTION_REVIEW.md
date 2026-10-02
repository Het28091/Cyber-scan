# Detection identity and mapping review — 2 October 2026

S3-04 developer review; independent review and a representative owner dataset are
still required. The implemented associations are related evidence, never a control
pass, compliance assessment or demonstrated attacker technique.

## Reconciled coverage

| Detection family | Declared scope | Specific framework association |
| --- | --- | --- |
| Built-in source/config/OpenAPI/Kubernetes | 21 fixed rules listed in the quality corpus; 21 positive rule matches and 11 clean cases | SECRET-LITERAL additionally relates to MITRE T1552.001; other 20 receive generic NIST evidence association only |
| Static HTTP | HTTP-content-security-policy, HTTP-x-content-type-options, HTTP-HSTS, COOKIE-FLAGS | HSTS and cookie rules have specific WSTG associations; the other two are generic only |
| Declared target workflows | ROLE-STATUS, ROLE-RESPONSE, CORS-CREDENTIALS | Status comparison and CORS have WSTG associations; response assertions are generic only |
| Local/advisory and external scanner findings | DEP-*, OSV-*, GITLEAKS-*, SEMGREP-*, TRIVY-* | Generic NIST association only; arbitrary upstream rule IDs are not automatically mapped to additional controls |
| Syft inventory, browser inventory and unavailable coverage | Assets/components/status rather than finding rules | No invented vulnerability or compliance findings |

Thus **5 of 28 fixed built-in rule IDs** have a specific curated association;
the other 23 have only the generic NIST identification association. This is mapping
coverage, not detection efficacy. Dynamic provider rule families are excluded from
that fixed denominator. The 21-rule corpus covers syntax/declaration rules only;
HTTP, roles, scanner adapters and provider protocols have separate tests and live
fixture jobs. None supplies a universal false-positive/false-negative estimate.

## Source reconciliation

The generic ID.RA-01 association supports organizing candidate vulnerability
evidence; it does not establish the broader organizational outcome. Refer to
[NIST CSF 2.0, Appendix A](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).
The existing catalog's NIST landing-page reference is indirect; this publication
is the direct review reference.

| Rule | Reviewed primary reference | What still requires operator validation |
| --- | --- | --- |
| SECRET-LITERAL | [MITRE T1552.001, revision 1.3](https://attack.mitre.org/techniques/T1552/001/) | Whether material is a real credential, exposed or usable; no attacker activity inferred |
| ROLE-STATUS | [WSTG 4.2 authorization schema testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/) | Account identity, response contents and business authorization; status alone is insufficient |
| CORS-CREDENTIALS | [WSTG 4.2 CORS testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/) | Browser behavior, actual sensitive responses and permitted origins |
| HTTP-HSTS | [WSTG 4.2 HSTS testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security/) | Deployment policy beyond the observed response |
| COOKIE-FLAGS | [WSTG 4.2 cookie attributes](https://owasp.github.io/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes) | Cookie purpose and session sensitivity |

All six references were consulted during this review. Existing mapping meanings
and catalog version remain unchanged. Regression coverage checks the reviewed
specific controls, explicit generic fallback, manual-review state, source digest
and unchanged finding identity. Adding a mapping requires a fresh rationale and
review; successful tests cannot establish the semantic accuracy of a new mapping.

## Fingerprints and duplicate evidence

Identity includes rule, asset, line, role and description. Presentation fields
(title, remediation, timestamp, scanner label) do not change identity. Moving code
to another line or changing an upstream advisory description can create a different
fingerprint; this is not semantic code tracking. Review/retest comparison must keep
those limitations visible and never automatically declare a disappearance fixed.

Repeated checkpoint deduplication previously mutated the input finding and could
append the same provenance repeatedly. It now returns independent copies and adds
each duplicate provenance entry only once. Evidence from distinct observations is
retained; primary scanner metadata remains on the finding itself. Tests verify
unchanged source objects, repeatability, consumer-edit isolation, duplicate evidence,
and distinct roles/locations/descriptions. No fingerprint format migration is made.
