import json,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from secaudit.config import Config,AIConfig
from secaudit.security import Scope,PolicyError
from secaudit.online import scan_dependencies,parse_response,provider_scope
from secaudit.scopefile import create
ROOT=Path(__file__).resolve().parents[1]
COMPONENT={'name':'Example_Package','version':'1.0.0','purl':'pkg:pypi/example-package@1.0.0'}
ADVISORY={'vulns':[{'id':'TEST-1','summary':'Synthetic advisory fixture'}]}
class InternetTests(unittest.TestCase):
    def config(self):return Config(mode='internet',modules=['online_dependencies'])
    def test_non_ai_mode_rejects_ai(self):
        with self.assertRaises(PolicyError):Config(mode='internet',ai=AIConfig(enabled=True)).validate()
    def test_offline_rejects_online_module(self):
        with self.assertRaises(PolicyError):Config(modules=['online_dependencies']).validate()
        with patch('secaudit.online.request') as network:
            with self.assertRaises(PolicyError):scan_dependencies([COMPONENT],Config())
            network.assert_not_called()
    def test_public_target_mode_boundary(self):
        data={'authorization':'synthetic authorization','origins':['https://test.example/'],'exclusions':['https://test.example/admin'],'environment':'test','profiles':['passive'],'max_requests':5,'max_seconds':5,'allowed_ips':['93.184.216.34']}
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))]):
            with self.assertRaisesRegex(PolicyError,'internet mode'):Scope(data,allow_public=False).check('https://test.example/')
            self.assertEqual(Scope(data).check('https://test.example/'),'93.184.216.34')
            with self.assertRaises(PolicyError):Scope(data).check('https://test.example/admin')
    def test_osv_only_receives_package_identity(self):
        component=dict(COMPONENT,source='private/path',secret='never-send',evidence=['private'])
        with patch('secaudit.online.provider_scope',return_value=object()),patch('secaudit.online.request',return_value=(200,[],json.dumps(ADVISORY).encode())) as transport:
            fs,usage,events=scan_dependencies([component,component],self.config());self.assertEqual(len(fs),1);self.assertEqual(usage['completed'],1)
            args=transport.call_args;self.assertEqual(args.args[0],'https://api.osv.dev/v1/query')
            self.assertEqual(json.loads(args.kwargs['body']),{'package':{'ecosystem':'PyPI','name':'example-package'},'version':'1.0.0'})
            self.assertIsNone(fs[0].cvss);self.assertEqual(fs[0].validation_status,'NEEDS MANUAL REVIEW')
    def test_osv_error_never_becomes_clean_result(self):
        for response in [(503,[],b'failure'),(302,[('Location','https://elsewhere.invalid')],b''),(200,[],b'not-json')]:
            with patch('secaudit.online.provider_scope',return_value=object()),patch('secaudit.online.request',return_value=response):
                fs,usage,events=scan_dependencies([COMPONENT],self.config());self.assertEqual(usage['failed'],1);self.assertEqual(usage['completed'],0);self.assertTrue(events)
    def test_budget_and_pagination_remain_visible(self):
        cfg=self.config();cfg.online_package_limit=1
        with patch('secaudit.online.provider_scope',return_value=object()),patch('secaudit.online.request',return_value=(200,[],json.dumps(dict(ADVISORY,next_page_token='more')).encode())) as network:
            _,usage,_=scan_dependencies([COMPONENT,dict(COMPONENT,version='2.0.0')],cfg);self.assertEqual(network.call_count,1);self.assertEqual(usage['completed'],0);self.assertEqual(usage['skipped'],2)
    def test_private_provider_dns_is_rejected(self):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]):
            with self.assertRaises(PolicyError):provider_scope()
    def test_withdrawn_advisory_is_not_a_finding(self):
        fs,_=parse_response({'vulns':[{'id':'TEST-1','withdrawn':'2026-01-01'}]},('PyPI','a','1'));self.assertEqual(fs,[])
    def test_scope_creation_no_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'scope.json';data=create('http://127.0.0.1:3000','Synthetic local demo',[],path);self.assertEqual(data['allowed_ips'],['127.0.0.1'])
            with self.assertRaises(FileExistsError):create('http://127.0.0.1:3000','other authorization',[],path)
    def test_internet_pipeline_no_ai_with_stub(self):
        with tempfile.TemporaryDirectory() as t:
            cfg=Path(t)/'config.json';cfg.write_text(json.dumps({'mode':'internet','source':str(ROOT/'demo/source'),'output':str(Path(t)/'runs'),'modules':['source','online_dependencies']}))
            code='''from unittest.mock import patch
from secaudit.cli import main
import sys
with patch('secaudit.online.provider_scope',return_value=object()),patch('secaudit.online.request',return_value=(200,[],b'{"vulns":[{"id":"TEST-1","summary":"Synthetic"}]}')),patch('secaudit.ai.Provider.health',side_effect=AssertionError('AI must not run')):
 raise SystemExit(main(['scan','--config',sys.argv[1]]))
'''
            p=subprocess.run([sys.executable,'-c',code,str(cfg)],cwd=ROOT,capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr)
            run=json.loads((Path(json.loads(p.stdout)['reports'])/'run.json').read_text());self.assertFalse(run['ai_usage']['enabled']);self.assertEqual(run['online_advisories']['completed'],1);self.assertTrue(run['network_policy']['online_advisories']);self.assertEqual(run['coverage'][1]['status'],'PARTIAL')
