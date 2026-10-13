"""Bounded CSP delivery observations; no policy-strength or DOM assessment."""
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .models import Finding


class _MetaCandidates(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = False

    def handle_starttag(self, tag, attrs):
        if tag != 'meta':
            return
        # Match HTML's first duplicate attribute behavior. A candidate in a
        # template/body is not evidence that a browser applies this policy.
        values = {}
        for name, value in attrs:
            values.setdefault(name, value or '')
        if (values.get('http-equiv', '').lower() == 'content-security-policy'
                and values.get('content', '').strip()):
            self.found = True


def csp_findings(url, status, headers, body=b''):
    if status in (204, 205, 301, 302, 303, 304, 307, 308):
        return []
    values = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value)
    types = [v.split(';', 1)[0].strip().lower() for v in values.get('content-type', [])]
    # Scope this recommendation to documents. Conflicting/unknown MIME types
    # remain uncertain; this does not certify MIME sniffing or worker policies.
    if len(types) == 1 and types[0] and types[0] not in ('text/html', 'application/xhtml+xml'):
        return []
    policies = values.get('content-security-policy', [])
    # Multiple enforced fields/policies are cumulative. Never call a policy weak
    # just because another field is empty, report-only, or permissive.
    if any(value.strip(' \t\r\n;,') for value in policies):
        return []
    if not policies:
        description = 'CSP response header absent.'
    elif any(value.strip() for value in policies):
        description = 'CSP response headers contain only whitespace or policy/directive separators.'
    else:
        description = 'CSP response headers empty.'
    if any(value.strip() for value in values.get('content-security-policy-report-only', [])):
        description += ' A report-only header is present; it monitors rather than enforces.'
    parser = _MetaCandidates()
    parsed = True
    try:
        parser.feed(body[:1_000_000].decode('utf-8', 'replace'))
    except (AssertionError, ValueError):
        parsed = False
    if not parsed:
        description += ' Static markup parsing was incomplete; meta policy delivery is unverified.'
    elif parser.found:
        description += ' Static markup contains a CSP meta candidate; browser applicability and strength are unverified.'
    else:
        description += ' No CSP meta candidate was recognized in the inspected static markup; dynamic DOM and encoding effects are not assessed.'
    if not types or len(types) != 1 or not types[0]:
        description += ' Document content type is unknown or ambiguous; verify applicability.'
    parts = urlsplit(url)
    asset = parts.scheme + '://' + parts.netloc + parts.path
    return [Finding(
        'HTTP-content-security-policy', 'CSP response header needs review', asset,
        description,
        'Review document and browser policy behavior before changing configuration. Prefer a tested CSP response header. '
        'Meta delivery has placement and directive limitations; report-only delivery does not enforce. '
        'Evaluate all enforced policies together and test the application workflow.',
        severity='LOW', confidence='HIGH', scanner_version='0.7.0', evidence=[description],
        impact='Delivery observation only; missing headers do not establish missing meta protection or exploitable XSS. '
               'Present policies are not certified as effective or restrictive.',
        reproduction='Inspect this response and its static CSP meta markup in an authorized browser.',
        retest='Repeat the assessment and verify effective browser policies and application behavior.'
    )]
