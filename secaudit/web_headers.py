"""Response-header observations; these do not establish exploitability.

Nosniff follows Fetch section 3.6. HSTS follows RFC 6797 sections 6.1 and 8.1.
CSP delivery context is delegated; no policy-strength assessment is claimed.
"""
import ipaddress
import re
from urllib.parse import urlsplit
from .models import Finding
from .web_csp import csp_findings

_TOKEN = r"[!#$%&'*+\-.^_\x60|~0-9A-Za-z]+"
_DIRECTIVE = re.compile(
    r'[ \t]*(' + _TOKEN + r')(?:[ \t]*=[ \t]*(' + _TOKEN +
    r'|"(?:[\x20-\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\x00-\x7f])*"))?[ \t]*(?:;|$)'
)


def hsts_state(value):
    """Return valid, disabled or invalid without storing the raw header."""
    directives = {}
    position = 0
    while position < len(value):
        # RFC 6797 permits empty directives around semicolon separators.
        empty = re.match(r'[ \t]*;', value[position:])
        if empty:
            position += empty.end()
            continue
        if not value[position:].strip(' \t'):
            break
        match = _DIRECTIVE.match(value, position)
        if match is None:
            return 'invalid'
        name, argument = match.groups()
        name = name.lower()
        if name in directives:
            return 'invalid'
        if argument is not None and argument.startswith('"'):
            argument = re.sub(r'\\([\x00-\x7f])', r'\1', argument[1:-1])
        directives[name] = argument
        position = match.end()
    age = directives.get('max-age')
    if age is None or not re.fullmatch(r'[0-9]+', age):
        return 'invalid'
    if 'includesubdomains' in directives and directives['includesubdomains'] is not None:
        return 'invalid'
    # Avoid converting attacker-controlled arbitrarily long decimal strings.
    return 'disabled' if not age.strip('0') else 'valid'


def header_findings(url, status, headers, body=b''):
    values = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value)
    asset_parts = urlsplit(url)
    asset = asset_parts.scheme + '://' + asset_parts.netloc + asset_parts.path
    findings = csp_findings(url, status, headers, body)

    def add(rule, title, description, remediation):
        findings.append(Finding(
            rule, title, asset, description, remediation,
            severity='LOW', confidence='HIGH', evidence=[description],
            impact='Observed response hardening gap; exploitability is not established.',
            reproduction='Request this URL and inspect the response headers.',
            retest='Repeat the request after changing the relevant response header.'
        ))

    redirect = status in (301, 302, 303, 307, 308)
    if not redirect:
        nosniff = values.get('x-content-type-options', [])
        if not nosniff or not nosniff[0].strip():
            add('HTTP-x-content-type-options', 'Missing x-content-type-options',
                'X-Content-Type-Options header empty on this response.' if nosniff else
                'X-Content-Type-Options header absent on this response.',
                'Set X-Content-Type-Options: nosniff.')
        elif nosniff[0].split(',', 1)[0].strip(' \t').lower() != 'nosniff':
            add('HTTP-NOSNIFF-INVALID', 'X-Content-Type-Options does not enable nosniff',
                'The first X-Content-Type-Options list value is not nosniff.',
                'Set X-Content-Type-Options: nosniff; remove conflicting values.')

    # Browsers do not record IP literals as HSTS hosts (RFC 6797 section 8.1.1).
    try:
        ipaddress.ip_address(asset_parts.hostname or '')
        ip_literal = True
    except ValueError:
        ip_literal = False
    if asset_parts.scheme == 'https' and not ip_literal:
        hsts = values.get('strict-transport-security', [])
        # RFC 6797 requires processing only the first field, not the last.
        value = hsts[0] if hsts else ''
        if not value.strip():
            add('HTTP-HSTS', 'Missing HSTS',
                'HTTPS response has empty HSTS.' if hsts else 'HTTPS response lacks HSTS.',
                'Review deployment and enable HSTS for this hostname.')
        else:
            state = hsts_state(value)
            if state == 'invalid':
                add('HTTP-HSTS-INVALID', 'Invalid HSTS policy',
                    'The first HSTS field has invalid syntax, duplicate directives or no valid max-age.',
                    'Send one valid Strict-Transport-Security field with a positive max-age.')
            elif state == 'disabled':
                add('HTTP-HSTS-DISABLED', 'HSTS policy explicitly disabled',
                    'The first HSTS field sets max-age to zero; this response removes its host policy.',
                    'Confirm whether disabling HSTS is intentional before selecting a positive max-age.')
    return findings
