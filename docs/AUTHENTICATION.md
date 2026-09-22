# Static authentication for passive assessment

Secaudit can send a pre-existing Bearer credential or session cookies on passive
GET/HEAD requests. It does not log in, refresh sessions, execute browser JavaScript
or compare roles. An HTTP 200 response alone does not prove a valid login.

Add an optional `authentication` object to an otherwise valid scope:

```json
{
  "type": "bearer",
  "env": "SECAUDIT_TARGET_SESSION",
  "origin": "https://app.example.test",
  "paths": ["/account", "/api"]
}
```

The origin must also be in `origins`; ordinary origin/path exclusions and pinned-IP
checks always apply first. Set `type` to `cookie` to send unquoted cookie pairs such
as `session=<value>; csrf=<value>` from the named environment variable. Only reference
names belong in scope files; literal credential fields are rejected. Each cookie
value must be at least eight characters. Bearer credentials must contain at least
eight characters, with no whitespace. Header controls and values over 8192 characters
are rejected. Credentials require HTTPS, except IP-literal loopback laboratory URLs.

Read a credential without placing it in shell history, then run the scanner:

```bash
read -rsp 'Session credential: ' SECAUDIT_TARGET_SESSION
export SECAUDIT_TARGET_SESSION
bash run.sh scan --config config/internet-web.json --target https://app.example.test/account --scope my-scope.json
unset SECAUDIT_TARGET_SESSION
```

For dashboard jobs, export the environment variable before starting the dashboard.
The same JSON authentication object can be supplied in its scope editor. There is
no credential-entry field or credential persistence in the dashboard.

Every redirect is rechecked. Credentials are regenerated only for matching origins
and path prefixes; other authorized destinations receive anonymous requests. A
separate origin, port or scheme cannot inherit the header. Ambient cookies, response
cookies and proxy settings are not adopted. Exclude logout and any known
state-changing GET endpoints explicitly: passive GET is not proof of no side effects.

Missing/invalid credentials block transmission. Rejection during preflight blocks
the scan. A 401/403 during crawling stops that crawl with an authentication rejection
event and incomplete coverage; strict mode fails. Authentication failures may also
appear as a redirect or a 200 login page, which this static mechanism cannot reliably
identify; manually verify the returned workflow.

Known credential values and their normal percent encodings are scrubbed from saved
evidence. Source/response bodies and raw scanner stderr are not persisted. Arbitrary
transformed or obfuscated server echoes cannot be universally recognized. Do not
share reports without review. External scanner sandboxes clear the credential
environment, and OSV/AI scopes do not contain the target authentication profile.
