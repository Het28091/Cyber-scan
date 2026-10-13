# Reliability improvement track — 13 October 2026

Owner request: make Secaudit dependable, targeting 99%. This is a target, not
a measured property. It does not replace the ten release gates or establish
security of a website.

## Measurement contract

Measure precision (TP / (TP + FP)) and recall (TP / (TP + FN)) separately for
each supported detector, plus crawl/endpoint coverage and completed-run rate.
A zero denominator is NOT MEASURED. Report sample counts and uncertainty.
Repeated URLs with the same configuration are correlated observations, not
independent benchmark cases. Do not inflate the denominator by duplicating them.

The proposed 99% precision target applies only to a frozen, independently labelled
held-out corpus and a declared detector set. Recall needs a separately approved
minimum and cannot be hidden behind precision. Unsupported vulnerability classes,
unreached authenticated routes and blocked requests remain NOT TESTED.
A small author-written regression suite is not this held-out benchmark.
Do not claim 99% general website reliability, detection or uptime.

## Prioritized work under S2-02/S2-05 and S3-03/S3-04

| Item | State in this change | Acceptance |
| --- | --- | --- |
| Parse nosniff and HSTS meaning instead of only checking nonempty strings | VERIFIED in Linux CI at d258e2e | Case, field order, disabled policy, malformed syntax, duplicate directives and safe controls |
| Stop suggesting HSTS on IP-literal URLs | VERIFIED in Linux CI at d258e2e | IPv4/IPv6 exclusions and named-host redirect regression |
| Preserve findings, cookie redaction and redirect scope boundaries | VERIFIED in Linux CI at d258e2e | Existing full suite plus new header integration checks |
| URL-first setup with automatic draft IP pins and explicit reviewed scope | VERIFIED in Linux CI at 2d2eca0 | Paste URL, review resolved scope, authorize; no automatic widening on redirects or DNS changes |
| Group equivalent findings across affected URLs | VERIFIED in Linux CI at 2d2eca0 | Presentation grouping only; original IDs, per-asset evidence and review revisions retained |
| Context-aware cookie attributes | IMPLEMENTED; 15 targeted Windows checks PASS; Linux CI pending | Validate SameSite values/order and whitespace; LOW manual-review observations, purpose/browser storage explicitly unknown |
| Context-aware CSP analysis | TODO | Meta CSP, report-only and multiple policies; no policy-strength claim from presence alone |
| Broader web detection through an isolated, scoped engine adapter | DESIGN REQUIRED | Owned vulnerable/clean fixtures; no engine networking that bypasses scope pins |
| Independent held-out benchmark | NOT STARTED | Frozen labelled cases, adjudicated disagreements, precision/recall by rule and scope |
| Owner website comparison | NOT VERIFIED | Independent HTTP observations and exported finding IDs; no inference from counts alone |

## Implemented header boundary

- Nosniff uses the first comma-separated value in the first header field, with
  ASCII case-insensitive matching. Nonempty arbitrary values no longer pass.
- HSTS parses directives, required decimal max-age (including quoted values),
  duplicates, extension syntax and valueless includeSubDomains. Zero max-age is
  identified as intentional policy removal, requiring review, not a proven exploit.
  Only the first HSTS field is evaluated. IP literals are excluded.
- CSP remains a response-header-presence observation. No CSP strength, meta policy,
  preload-list or inherited parent HSTS evaluation is claimed.
- New checks retain LOW severity and manual-review status; confidence refers to the
  response observation. Raw header values and cookie values are not added to evidence.
- Offline scanning stays independent. Optional AI setup is simplified; AI does not add detection coverage.

Standards: [Fetch nosniff](https://fetch.spec.whatwg.org/#x-content-type-options-header)
and [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797).

Server AI setup: VERIFIED in Linux CI at 2d2eca0. Explicit operator file/environment configuration can be loaded without secrets or network probes; browser consent and actual preflight remain mandatory. Protocol fixtures do not replace real-provider acceptance.

## Cookie observation continuation

`COOKIE-FLAGS` detector version 0.7.0 parses each Set-Cookie field independently,
trims attribute whitespace, validates the final SameSite setting, and explains
SameSite=None without Secure as possible browser rejection. Observations are LOW,
HIGH-confidence observations requiring manual review, not confirmed session theft
or CSRF. Cookie names/values/domain/path and URL query values remain redacted.
No inference of cookie purpose, expiry/deletion, browser storage or exploitability
is made. Secure/HttpOnly are presence attributes even when a value is supplied.
Overlong attribute values are ignored per the browser parsing specification.
Changing descriptions changes finding fingerprints; old reports/reviews remain
immutable and comparisons across detector versions need manual reconciliation.

Parsing reference: [HTTPWG cookie processing, sections 5.6–5.7](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html).
Tests are authored fixtures, not an independent held-out benchmark.
