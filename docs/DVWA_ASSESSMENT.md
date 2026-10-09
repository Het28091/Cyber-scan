# DVWA assessment — 9 October 2026

Owner-authorized target: `http://10.87.119.94:8080/security.php`.
Baseline: `c52bea65ca19e222ce9bc725b754d8027167ee93`.
Repaired and tested source: `ca13ace488bcc39adec03cf5d971f8c157dc1ecb`.
Tasks: S2-02, S2-05, S3-01 and S3-04; bounded evidence, not whole-task or
spiral acceptance. No API key, AI call, login, form submission or exploit payload
was used. The owner requested continuation without supplying a dedicated session,
then authorized HTTPS preparation.

## Findings and correction

The baseline CLI returned zero findings on HTTP 302 to `login.php`. Scope
correctly blocked the other path, but the scanner skipped cookie checks before
redirect handling. Independent inspection observed three Set-Cookie headers
without Secure, HttpOnly or SameSite.

The repair checks redirect cookies and HTTPS transport policy before redirect
navigation, checkpoints evidence, and states that destination content was not
tested. Document-header checks are not applied to redirects. Scope pins,
credential restrictions and manual-review state remain intact. Identical cookie
observations are consolidated: one finding does not mean only one affected cookie.

| Response | Status | Secaudit findings | Independent agreement |
| --- | --- | --- | --- |
| Original HTTP `/security.php`, repaired scanner | 302 | Missing cookie flags | 1 TP, 0 FP, 0 FN |
| New HTTPS `/security.php` | 302 | Missing cookie flags; HSTS | 2 TP, 0 FP, 0 FN |
| New HTTPS `/login.php` | 200 | Missing cookie flags, HSTS, CSP, X-Content-Type-Options | 4 TP, 0 FP, 0 FN |

These counts compare unique header/cookie observations on consecutive responses,
not confirmed exploitable vulnerabilities. HSTS describes the newly prepared
lab proxy, not the original HTTP application's vulnerability count. Cookie
purpose still requires manual review.

**Whole-DVWA detection accuracy is NOT ESTABLISHED.** No SQL injection, XSS,
command injection, upload, CSRF or authenticated workflow was tested. Built-in
web scanning is passive; AI supplies remediation suggestions, not active probes.
The PHP exercises are not a supported built-in source-analysis corpus. Broader
accuracy measurement needs an explicit case inventory, authenticated access,
expected results and supported detection methods. Do not extrapolate these
results into 100% DVWA accuracy or a clean security assessment.

## Verification

- Kali Linux x86_64, Python 3.13.12: **174 tests PASS in 9.755 seconds**, source
  `ca13ace`; VM log `artifacts/checkpoints/dvwa-oct9/tests.log`.
- Four new tests cover unsafe/safe redirect cookies, HTTPS HSTS, absent Location,
  cookie-value omission, blocked navigation and evidence checkpointing.
- Actual CLI scans generated both PDF reports with AI disabled.
- [CI run 37962681926](https://github.com/Het28091/Cyber-scan/actions/runs/37962681926)
  completed successfully at this source.
- Sanitized evidence: [baseline](evidence/dvwa-baseline-oct9.json),
  [repaired HTTP](evidence/dvwa-http-oct9.json),
  [HTTPS comparisons](evidence/dvwa-https-oct9.json).

Repeat only while this exact owner lab remains authorized:

```sh
cd /home/kali/Cyber-scan
.venv/bin/python -m integration.dvwa_acceptance
```

The command performs one preflight HEAD, one scanner GET and one independent
GET, with no redirect following. It is deliberately absent from CI. Baseline
and each HTTPS page comparison used the same three-request budget. A separate
loopback GET verified the backend before HTTPS preparation.

Reports remain on Kali under `/home/kali/Cyber-scan/artifacts/checkpoints/dvwa-oct9/`:
HTTP `runs/3d8204f00c274cc8a6ffc01d5cd3d20d/`, HTTPS redirect
`https-runs/db02ba2872404a40b63e61c91c026b01/`, HTTPS login
`https-runs/b059959d3918423dbd38f07a9f06cfac/`.
Published summaries omit cookies and response bodies.

## HTTPS lab handover

Endpoint: `https://10.87.119.94:8443/security.php`; login at `/login.php`.
Unprivileged standalone nginx forwards to the verified `127.0.0.1:8080` backend.
The original HTTP service remains available. No global certificate trust or
system nginx configuration changed. An initial config test failed on nginx's
default system temp path; all temp paths were then moved into the private lab
directory and configuration validation passed before starting the service.

Lab directory: `/home/kali/Cyber-scan/artifacts/checkpoints/dvwa-oct9/https`.
Files: `lab.crt`, `lab.key`, `nginx.conf`, `nginx.pid`; directory mode 0700, key
mode 0600. The private key stays on Kali. Certificate expiration:
**23 October 2026 16:57:29 UTC**. SHA-256 fingerprint:

```text
6F:C5:D6:67:F4:D1:19:E9:0A:18:DF:D2:89:5D:E3:E7:C6:3B:33:5D:0D:1F:A4:D4:EF:F9:96:4D:FA:EB:27:E9
```

This private-lab certificate is self-signed: browsers will not trust it
automatically. Trust this specific verified certificate for lab use. Secaudit
used process-scoped `SSL_CERT_FILE` pointing at `lab.crt`; certificate and hostname
verification stayed enabled. No insecure TLS bypass was added. HTTPS does not
authenticate the scanner to DVWA.

The proxy does not automatically restart after reboot. To stop it on Kali:

```sh
lab=/home/kali/Cyber-scan/artifacts/checkpoints/dvwa-oct9/https
/usr/sbin/nginx -p "$lab/" -c "$lab/nginx.conf" -s quit
```

Restart with the same command without `-s quit`, while the certificate and VM IP
remain valid. Renew/review the certificate after expiry or IP change.
Authenticated acceptance still needs an owner-prepared dedicated session supplied
privately on Kali. Real AI acceptance and production release gates remain open.
