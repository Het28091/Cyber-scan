"""CSP delivery regressions; deliberately not a CSP security evaluator."""
import json
import unittest
from unittest.mock import patch

from secaudit.web_csp import csp_findings, script_directive_gaps
from secaudit.network import scan_web
from secaudit.security import Scope


class CSPDeliveryTests(unittest.TestCase):
    url = 'https://owned.example.invalid/'

    def test_non_document_and_no_content_responses(self):
        for mime in ('application/json', 'text/plain', 'image/png', 'text/javascript'):
            self.assertEqual(csp_findings(self.url, 200, [('Content-Type', mime)]), [])
        for status in (204, 205, 301, 302, 303, 304, 307, 308):
            self.assertEqual(csp_findings(self.url, status, []), [])
        for mime in ('text/html; charset=UTF-8', 'application/xhtml+xml'):
            self.assertEqual(len(csp_findings(self.url, 200, [('Content-Type', mime)])), 1)

    def test_empty_policies_and_report_only_context(self):
        for policy in ('', ' ', '; ;', ', ; ,'):
            findings = csp_findings(self.url, 200, [
                ('Content-Security-Policy', policy),
                ('Content-Security-Policy-Report-Only', "default-src 'none'")])
            self.assertEqual(len(findings), 1)
            self.assertIn('monitors rather than enforces', findings[0].description)

    def test_multiple_enforced_fields_do_not_claim_weakness(self):
        for policy in ("default-src 'none'", "script-src * 'unsafe-inline'"):
            self.assertEqual(csp_findings(self.url, 200, [
                ('Content-Security-Policy', ''), ('Content-Security-Policy', policy),
                ('Content-Security-Policy-Report-Only', "default-src 'none'")]), [])

    def test_meta_candidate_does_not_certify_enforcement_or_leak_content(self):
        body = b'<head><META HTTP-EQUIV="Content-Security-Policy" content="script-src PRIVATE_NONCE"></head>'
        finding = csp_findings(self.url, 200, [('Content-Type', 'text/html')], body)[0]
        self.assertIn('contains a CSP meta candidate', finding.description)
        self.assertIn('unverified', finding.description)
        self.assertNotIn('PRIVATE_NONCE', json.dumps(finding.to_dict()))
        self.assertEqual(finding.severity, 'LOW')
        self.assertEqual(finding.validation_status, 'NEEDS MANUAL REVIEW')

    def test_comments_script_and_report_only_meta_are_not_candidates(self):
        meta = '<meta http-equiv="Content-Security-Policy" content="default-src none">'
        for body in ('<!--' + meta + '-->', '<script>const x = `' + meta + '`;</script>',
                     meta.replace('Content-Security-Policy', 'Content-Security-Policy-Report-Only'),
                     '<meta http-equiv="other" http-equiv="Content-Security-Policy" content="x">'):
            self.assertIn('No CSP meta candidate', csp_findings(self.url, 200, [], body.encode())[0].description)

    def test_scan_passes_bounded_body_and_preserves_redaction(self):
        scope = Scope(dict(authorization='owned csp fixture', origins=[self.url], exclusions=[],
                           environment='test', profiles=['passive'], allowed_ips=['127.0.0.1'],
                           max_requests=1, max_seconds=5))
        body = b'<meta http-equiv="Content-Security-Policy" content="default-src PRIVATE_SOURCE">'
        with patch('secaudit.network.request', return_value=(200, [('Content-Type', 'text/html')], body)), \
                patch('secaudit.network.time.sleep'):
            findings, _, _ = scan_web(self.url, scope, lambda *args: None)
        csp = next(f for f in findings if f.rule == 'HTTP-content-security-policy')
        self.assertIn('contains a CSP meta candidate', csp.description)
        self.assertNotIn('PRIVATE_SOURCE', json.dumps([f.to_dict() for f in findings]))

    def test_malformed_markup_does_not_abort_header_review(self):
        findings = csp_findings(self.url, 200, [], b'<![invalid declaration]>')
        self.assertEqual(len(findings), 1)
        # HTMLParser's handling of invalid declarations varies by Python version.
        for error in (AssertionError, ValueError):
            with patch('secaudit.web_csp._MetaCandidates.feed', side_effect=error):
                findings = csp_findings(self.url, 200, [], b'<![invalid declaration]>')
            self.assertIn('parsing was incomplete', findings[0].description)

    def test_script_fallbacks_and_multiple_policies(self):
        for fields in (["default-src 'none'"], ['SCRIPT-SRC'],
                       ["img-src *", "script-src 'self'"],
                       ["img-src *, script-src 'self'"],
                       ["script-src-elem 'none'", "script-src-attr 'none'"],
                       ['sandbox'], ['sandbox allow-scripts']):
            with self.subTest(fields=fields):
                self.assertEqual(script_directive_gaps(fields), [])

    def test_script_categories_and_unknown_directives(self):
        self.assertEqual(script_directive_gaps(['script-src-elem']), ['script attributes'])
        self.assertEqual(script_directive_gaps(['script-src-attr']), ['script elements'])
        for policy in ('img-src *', 'script-src-typo none', 'report-uri https://private.invalid',
                       'default-src=none', 'report-to script-src'):
            with self.subTest(policy=policy):
                self.assertEqual(script_directive_gaps([policy]), ['script elements', 'script attributes'])

    def test_report_only_does_not_fill_enforced_directive_gaps(self):
        findings = csp_findings(self.url, 200, [
            ('Content-Security-Policy', 'img-src https://PRIVATE_SOURCE'),
            ('Content-Security-Policy-Report-Only', "default-src 'none'")])
        self.assertEqual([f.rule for f in findings], ['HTTP-CSP-SCRIPT-COVERAGE'])
        self.assertIn('script elements, script attributes', findings[0].description)
        self.assertNotIn('PRIVATE_SOURCE', json.dumps(findings[0].to_dict()))
        self.assertIn('not certified', findings[0].impact)

    def test_duplicate_directive_values_do_not_change_declaration_coverage(self):
        self.assertEqual(script_directive_gaps(["script-src 'none'; script-src *"]), [])
        self.assertEqual(script_directive_gaps(["script-src *; script-src 'none'"]), [])
