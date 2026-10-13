"""Standards-derived regression cases, not an independent accuracy benchmark."""
import json
import unittest
from unittest.mock import patch
from secaudit.web_headers import header_findings, hsts_state
from secaudit.network import scan_web
from secaudit.security import Scope


class HeaderPolicyTests(unittest.TestCase):
    def rules(self, headers, url='https://owned.example.invalid/', status=200):
        return {f.rule for f in header_findings(url, status, headers)}

    def test_nosniff_first_value_and_case(self):
        cases = [
            ('nosniff', False), (' NoSnIfF\t', False),
            ('nosniff, junk', False), ('junk, nosniff', True),
            ('true', True), ('"nosniff"', True), ('nosniff; extra', True),
        ]
        for value, invalid in cases:
            with self.subTest(value=value):
                self.assertEqual('HTTP-NOSNIFF-INVALID' in self.rules(
                    [('X-Content-Type-Options', value)]), invalid)
        for first, second, invalid in [('nosniff','wrong',False), ('wrong','nosniff',True)]:
            with self.subTest(first=first):
                self.assertEqual('HTTP-NOSNIFF-INVALID' in self.rules([
                    ('X-Content-Type-Options', first), ('x-content-type-options', second)]), invalid)

    def test_hsts_syntax_and_effect(self):
        cases = [
            ('max-age=31536000; includeSubDomains', 'valid'),
            ('MAX-AGE = "86400"; preload', 'valid'),
            ('; max-age=1; ;', 'valid'),
            ('max-age="\\1"; extension="a;b"', 'valid'),
            ('max-age=' + '9'*5000, 'valid'),
            ('max-age=000', 'disabled'),
            ('max-age="0"; includeSubDomains', 'disabled'),
            ('includeSubDomains', 'invalid'),
            ('max-age=-1', 'invalid'), ('max-age=1.5', 'invalid'),
            ('max-age=1, max-age=2', 'invalid'),
            ('max-age=1; MAX-AGE=2', 'invalid'),
            ('max-age=1; includeSubDomains=true', 'invalid'),
            ('max-age=1; extension; extension', 'invalid'),
            ('max-age="12', 'invalid'), ('max-age=1; broken value', 'invalid'),
            ('max-age=1\n', 'invalid'),
        ]
        for value, expected in cases:
            with self.subTest(value=value[:80]):
                self.assertEqual(hsts_state(value), expected)

    def test_hsts_first_field_and_ip_literals(self):
        disabled=[('Strict-Transport-Security','max-age=0'),
                  ('strict-transport-security','max-age=86400')]
        enabled=list(reversed(disabled))
        self.assertIn('HTTP-HSTS-DISABLED', self.rules(disabled))
        self.assertFalse(any(rule.startswith('HTTP-HSTS') for rule in self.rules(enabled)))
        for url in ('http://owned.example.invalid/', 'https://127.0.0.1/', 'https://[::1]/'):
            with self.subTest(url=url):
                self.assertFalse(any(rule.startswith('HTTP-HSTS') for rule in self.rules([],url)))

    def test_redirect_preserves_transport_checks_only(self):
        self.assertEqual(self.rules([],status=302), {'HTTP-HSTS'})
        self.assertEqual(self.rules([
            ('Strict-Transport-Security','max-age=0')],status=302), {'HTTP-HSTS-DISABLED'})

    def test_csp_multiple_fields_and_report_only(self):
        self.assertNotIn('HTTP-content-security-policy',self.rules([
            ('Content-Security-Policy',''), ('Content-Security-Policy',"default-src 'none'")]))
        self.assertIn('HTTP-content-security-policy',self.rules([
            ('Content-Security-Policy-Report-Only',"default-src 'none'")]))

    def test_scan_integration_keeps_evidence_and_redacts_header_values(self):
        url='https://owned.example.invalid/'
        scope=Scope(dict(authorization='owned header fixture', origins=[url], exclusions=[],
                         environment='test', profiles=['passive'], allowed_ips=['127.0.0.1'],
                         max_requests=1, max_seconds=5))
        headers=[('Content-Security-Policy',"default-src 'none'"),
                 ('X-Content-Type-Options','PRIVATE_HEADER_MARKER'),
                 ('Strict-Transport-Security','max-age=0'),
                 ('Set-Cookie','session=PRIVATE_COOKIE_MARKER; Secure; HttpOnly; SameSite=Lax')]
        checkpoints=[]
        with patch('secaudit.network.request',return_value=(200,headers,b'')), \
             patch('secaudit.network.time.sleep'):
            findings,assets,events=scan_web(url,scope,lambda f,a:checkpoints.append((list(f),list(a))))
        self.assertEqual({f.rule for f in findings},{'HTTP-NOSNIFF-INVALID','HTTP-HSTS-DISABLED'})
        self.assertEqual(len(assets),1)
        self.assertTrue(checkpoints)
        serialized=json.dumps([f.to_dict() for f in findings])
        self.assertNotIn('PRIVATE_HEADER_MARKER',serialized)
        self.assertNotIn('PRIVATE_COOKIE_MARKER',serialized)
        self.assertTrue(all(f.validation_status=='NEEDS MANUAL REVIEW' for f in findings))
