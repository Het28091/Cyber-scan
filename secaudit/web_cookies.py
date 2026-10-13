"""Redacted Set-Cookie attribute observations, not a browser cookie store."""
from urllib.parse import urlsplit

from .models import Finding


def cookie_findings(url, headers):
    """Review attributes independently on each Set-Cookie response field.

    Attribute names are case-insensitive and optional whitespace is stripped
    on both sides of '='. The last SameSite attribute determines its setting.
    Cookie acceptance, purpose, expiry and application CSRF defenses are unknown.
    """
    parts = urlsplit(url)
    asset = parts.scheme + '://' + parts.netloc + parts.path
    findings = []
    for name, value in headers:
        if name.lower() != 'set-cookie':
            continue
        attrs = {}
        # Never split on commas: Expires contains a comma. Never persist names,
        # values, domains or paths from the header, including malformed values.
        for segment in value.split(';')[1:]:
            key, _, argument = segment.partition('=')
            argument = argument.strip(' \t')
            if len(argument) <= 1024:
                attrs[key.strip(' \t').lower()] = argument
        concerns = []
        missing = {'secure', 'httponly', 'samesite'} - attrs.keys()
        if missing:
            concerns.append('Missing explicit attributes: ' + ', '.join(sorted(missing)) + '.')
        same_site = attrs.get('samesite', '').lower()
        if 'samesite' in attrs and same_site not in ('lax', 'strict', 'none'):
            concerns.append('The final SameSite attribute is empty or unrecognized; browser defaults apply.')
        if same_site == 'none' and 'secure' not in attrs:
            concerns.append('SameSite=None lacks Secure; modern browsers may reject this cookie.')
        if not concerns:
            continue
        description = ' '.join(concerns)
        findings.append(Finding(
            'COOKIE-FLAGS', 'Cookie attributes need contextual review', asset,
            description,
            'Determine cookie purpose and whether it is being deleted. Use Secure for sensitive cookies over HTTPS; '
            'use HttpOnly when JavaScript access is unnecessary. Choose SameSite for the application workflow; '
            'None requires Secure. Verify browser behavior and CSRF defenses.',
            severity='LOW', confidence='HIGH', scanner_version='0.7.0',
            evidence=['At least one Set-Cookie field: ' + description,
                      'Cookie names and values omitted; purpose and browser storage not assessed.'],
            impact='Attribute observation only. Missing HttpOnly may be intentional for JavaScript-readable cookies; '
                   'missing or invalid SameSite does not establish absence of browser protection or a CSRF vulnerability.',
            reproduction='Inspect Set-Cookie attributes on this response, including redirects, in an authorized browser.',
            retest='Repeat the request and verify cookie storage and the intended application workflow.'
        ))
    return findings
