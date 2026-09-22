import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from secaudit.config import Config, AIConfig
from secaudit.inventory import parse_manifest
from secaudit.jobs import Jobs
from secaudit.models import Finding, dedup
from secaudit.security import Scope, PolicyError, write_json


class ReviewTests(unittest.TestCase):
    def test_requirements_account_for_every_declaration(self):
        text = '''requests[socks]==2.31.0 ; python_version < "3.10"
other>=2
wild==1.*
urlpkg @ https://user:secret@invalid.example/a.whl
-r private.txt
not a requirement!
# comment
'''
        components, stats = parse_manifest('requirements.txt', text)
        self.assertEqual([c['name'] for c in components], ['requests'])
        self.assertEqual(stats['total'], 6)
        self.assertEqual((stats['pinned'],stats['unresolved'],stats['unsupported'],stats['invalid'],stats['conditional']), (1,3,1,1,1))
        self.assertNotIn('secret', json.dumps(stats))

    def test_hash_continuations_and_normalization(self):
        components, stats = parse_manifest('requirements-dev.txt', 'My_Pkg==1.2 \\\n --hash=sha256:abc # comment\n')
        self.assertEqual(components[0]['name'], 'my-pkg')
        self.assertEqual(stats['pinned'], 1)

    def test_no_parser_is_visible_not_empty_success(self):
        with patch.dict('sys.modules', {'packaging.requirements': None}):
            components, stats = parse_manifest('requirements.txt', 'a==1')
        self.assertEqual(components, [])
        self.assertEqual(stats['unsupported'], 1)

    def test_npm_v1_nested_and_v3_links(self):
        _, stats = parse_manifest('package-lock.json', json.dumps({'lockfileVersion':1,'dependencies':{'a':{'version':'1.0.0','dependencies':{'b':{'version':'2.0.0'}}}}}))
        self.assertEqual(stats['pinned'], 2)
        components, stats = parse_manifest('npm-shrinkwrap.json', json.dumps({'lockfileVersion':3,'packages':{'':{},'node_modules/@a/b':{'version':'1.0.0'},'node_modules/local':{'link':True}}}))
        self.assertEqual(stats['unresolved'], 1)
        self.assertEqual(components[0]['purl'], 'pkg:npm/%40a/b@1.0.0')

    def test_malformed_lock_is_counted(self):
        for lock in ('[]','{','{"lockfileVersion":3,"packages":[]}'):
            with self.subTest(lock=lock):
                components, stats = parse_manifest('package-lock.json', lock)
                self.assertEqual(components, [])
                self.assertEqual(stats['invalid'], 1)

    def test_dns_is_pinned_once_but_paths_are_always_checked(self):
        scope = Scope(dict(authorization='owned fixture',origins=['http://test.example/'],exclusions=['http://test.example/admin'],environment='test',profiles=['passive'],max_requests=10,max_seconds=30,allowed_ips=['127.0.0.1']))
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',80))]) as dns:
            self.assertEqual(scope.check('http://test.example/a'),'127.0.0.1')
            self.assertEqual(scope.check('http://test.example/b'),'127.0.0.1')
            with self.assertRaises(PolicyError): scope.check('http://test.example/admin')
            self.assertEqual(dns.call_count,1)
        # Changed resolver output cannot redirect subsequent pinned connections.
        with patch('socket.getaddrinfo',side_effect=AssertionError('must not re-resolve')):
            self.assertEqual(scope.check('http://test.example/c'),'127.0.0.1')

    def test_ai_gate_rejects_before_provider(self):
        with patch.dict(os.environ, {'SECAUDIT_EXPERIMENTAL_AI':'0'}):
            with self.assertRaisesRegex(PolicyError,'experimental'):
                Config(mode='local-ai').validate()
            from secaudit.ai import Provider
            with self.assertRaisesRegex(PolicyError,'disabled'):
                Provider(Config(mode='connected-ai',ai=AIConfig(enabled=True)))

    def test_distinct_same_location_findings_survive(self):
        a=Finding('R','title','asset','observation a','fix')
        b=Finding('R','title','asset','observation b','fix')
        self.assertEqual(len(dedup([a,a,b])),2)
        self.assertEqual(len(a.to_dict()['id']),32)

    def test_retention_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'.jobs';folder.mkdir()
            for i in range(202):
                ident=f'{i:032x}'
                write_json(folder/(ident+'.json'),dict(id=ident,created=f'{i:04}',status='COMPLETED'))
                (folder/(ident+'.config.json')).write_text('{}')
                (folder/(ident+'.scope')).write_text('{}')
            evidence=Path(temp)/('0'*32);evidence.mkdir();(evidence/'run.json').write_text('{}')
            jobs=Jobs(temp)
            try:
                self.assertEqual(len(jobs.list(None)),200)
                self.assertFalse(list(folder.glob('*.config.json')))
                self.assertFalse(list(folder.glob('*.scope')))
                self.assertTrue((evidence/'run.json').exists())
            finally: jobs.close()

    def test_failed_job_has_reason_and_removes_config(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs=Jobs(temp)
            try:
                job=jobs.submit({'source':'/does-not-exist-secaudit','preset':'offline'})
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    result=jobs.list()[0]
                    if result['status']=='FAILED' and not (jobs.folder/(job['id']+'.config.json')).exists(): break
                    time.sleep(.05)
                self.assertEqual(result['status'],'FAILED')
                self.assertEqual(result['diagnostic']['exit_code'],2)
                self.assertEqual(result['diagnostic']['code'],'PREFLIGHT_OR_INPUT_REJECTED')
                self.assertFalse((jobs.folder/(job['id']+'.config.json')).exists())
            finally: jobs.close()

if __name__=='__main__': unittest.main()
