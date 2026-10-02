import hashlib
import json
import unittest
from secaudit.frameworks import DATA,apply_mappings
from secaudit.models import Finding


class MappingTraceabilityTests(unittest.TestCase):
    def test_reviewed_specific_mappings_and_generic_fallback_preserve_identity(self):
        expected={'SECRET-LITERAL':'T1552.001','ROLE-STATUS':'WSTG-v42-ATHZ-02',
            'CORS-CREDENTIALS':'WSTG-v42-CLNT-07','HTTP-HSTS':'WSTG-v42-CONF-07',
            'COOKIE-FLAGS':'WSTG-v42-SESS-02'}
        self.assertEqual(set(json.loads(DATA.read_bytes())['rules']),set(expected))
        for rule,control in list(expected.items())+[('SEMGREP-owned-unmapped',None),('ROLE-RESPONSE',None)]:
            finding=Finding(rule,'Owned mapping fixture','owned.py','Observation','Review').to_dict()
            identity=(finding['id'],finding['fingerprint']);run={'findings':[finding]}
            apply_mappings(run)
            with self.subTest(rule=rule):
                self.assertEqual((finding['id'],finding['fingerprint']),identity)
                self.assertEqual({m['control'] for m in finding['mappings']},{'ID.RA-01',control} if control else {'ID.RA-01'})
                self.assertTrue(all(m['status']=='NEEDS MANUAL REVIEW' and m['rationale'] for m in finding['mappings']))
                self.assertEqual(run['framework_snapshot']['sha256'],hashlib.sha256(DATA.read_bytes()).hexdigest())
