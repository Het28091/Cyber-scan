"""Owned attribute fixtures; not independent browser or accuracy acceptance."""
import json
import unittest

from secaudit.web_cookies import cookie_findings


class CookieObservationTests(unittest.TestCase):
    def scan(self, value):
        return cookie_findings('https://owned.example.invalid/login?secret=query', [('Set-Cookie', value)])

    def test_case_whitespace_and_boolean_attributes(self):
        for value in ('a=b; Secure; HttpOnly; SameSite=Lax',
                      'a=b; SECURE = ignored; HttpOnly = ignored; SameSite = sTrIcT',
                      'a=b; Secure; HttpOnly; SameSite=None',
                      'a=b; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax'):
            with self.subTest(value=value):
                self.assertEqual(self.scan(value), [])

    def test_invalid_and_duplicate_samesite(self):
        for value in ('', 'garbage', '"Lax"', 'Lax; SameSite=garbage'):
            with self.subTest(value=value):
                finding = self.scan('a=b; Secure; HttpOnly; SameSite=' + value)[0]
                self.assertIn('empty or unrecognized', finding.description)
                self.assertEqual(finding.severity, 'LOW')
                self.assertEqual(finding.validation_status, 'NEEDS MANUAL REVIEW')
        self.assertEqual(self.scan('a=b; Secure; HttpOnly; SameSite=garbage; SameSite=Lax'), [])

    def test_none_without_secure_explains_possible_rejection(self):
        finding = self.scan('a=b; HttpOnly; SameSite=None')[0]
        self.assertIn('may reject', finding.description)
        self.assertIn('secure', finding.description)

    def test_defaults_purpose_and_redaction(self):
        finding = self.scan('PRIVATE_NAME=PRIVATE_VALUE; Path=/PRIVATE_PATH; Domain=PRIVATE_DOMAIN')[0]
        self.assertIn('JavaScript-readable', finding.impact)
        self.assertIn('does not establish', finding.impact)
        self.assertEqual(finding.confidence, 'HIGH')
        serialized = json.dumps(finding.to_dict())
        self.assertNotIn('PRIVATE', serialized)
        self.assertNotIn('secret=query', serialized)

    def test_fields_are_independent_and_long_attribute_is_ignored(self):
        findings = cookie_findings('https://owned.example.invalid/', [
            ('Set-Cookie', 'a=b; Secure; HttpOnly; SameSite=Lax'),
            ('set-cookie', 'c=d; HttpOnly; SameSite=None'),
            ('Cookie', 'not-a-response-cookie')])
        self.assertEqual(len(findings), 1)
        self.assertEqual(self.scan('a=b; Secure; HttpOnly; SameSite=Lax; SameSite=' + 'x'*1025), [])
