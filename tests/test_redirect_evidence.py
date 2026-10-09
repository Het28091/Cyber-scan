import json
import unittest
from unittest.mock import patch

from secaudit.models import dedup
from secaudit.network import scan_web
from secaudit.security import Scope


class RedirectEvidenceTests(unittest.TestCase):
    def run_scan(self, headers, secure=False):
        target=('https' if secure else 'http')+'://127.0.0.1/security.php'
        scope=Scope(dict(authorization='owned redirect fixture', origins=[target],
                         exclusions=[], environment='test', profiles=['passive'],
                         allowed_ips=['127.0.0.1'], max_requests=1, max_seconds=5))
        checkpoints=[]
        with patch('secaudit.network.request', return_value=(302, headers, b'<a href="/setup.php">setup</a>')) as req:
            findings, assets, events=scan_web(target, scope, lambda f,a: checkpoints.append((list(f),list(a))))
        self.assertEqual(req.call_count,1)
        self.assertEqual(assets,[{'asset':target,'status':302}])
        self.assertTrue(checkpoints)
        self.assertTrue(any(e.startswith('REDIRECT_RESPONSE') for e in events))
        return dedup(findings),events

    def test_redirect_cookie_detected_without_following_login_or_leaking_value(self):
        fs,events=self.run_scan([('Location','/login.php'),('Set-Cookie','session=private-cookie-value; Path=/')])
        self.assertEqual([f.rule for f in fs],['COOKIE-FLAGS'])
        self.assertIn('Out-of-scope redirect blocked',events)
        self.assertNotIn('private-cookie-value',json.dumps([f.to_dict() for f in fs]))

    def test_safe_cookie_and_document_header_absence_do_not_raise(self):
        fs,_=self.run_scan([('Location','/login.php'),('Set-Cookie','session=private-cookie-value; Secure; HttpOnly; SameSite=Lax')])
        self.assertEqual(fs,[])

    def test_https_redirect_still_checks_hsts(self):
        fs,_=self.run_scan([('Location','/login.php')],secure=True)
        self.assertEqual([f.rule for f in fs],['HTTP-HSTS'])

    def test_missing_location_still_retains_cookie_evidence(self):
        fs,_=self.run_scan([('Set-Cookie','session=private-cookie-value')])
        self.assertEqual([f.rule for f in fs],['COOKIE-FLAGS'])
