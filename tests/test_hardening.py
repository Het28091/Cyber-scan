import base64,http.client,json,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from secaudit.security import Scope,PolicyError,canonical
from secaudit.jobs import Jobs
from secaudit.store import Store
from secaudit.preflight import doctor
from secaudit.config import Config
ROOT=Path(__file__).resolve().parents[1]
class HardeningTests(unittest.TestCase):
    def scope(self):return {'authorization':'synthetic test','origins':['http://127.0.0.1/'],'exclusions':['http://127.0.0.1/admin'],'environment':'lab','profiles':['passive'],'max_requests':2,'max_seconds':2,'allowed_ips':['127.0.0.1']}
    def test_scope_wrong_shapes_fail_cleanly(self):
        for data in (None,[],42,dict(self.scope(),origins='http://127.0.0.1/'),dict(self.scope(),allowed_ips=[1]),dict(self.scope(),exclusions=None),dict(self.scope(),environment={}),dict(self.scope(),unknown=True)):
            with self.subTest(data=data),self.assertRaises(PolicyError):Scope(data)
    def test_ambiguous_urls_rejected_before_dns(self):
        paths=['http://127.0.0.1:0/','http://127.0.0.1:65536/','http://127.0.0.1/admin;param','http://127.0.0.1/admin%3bparam','http://127.0.0.1/%ff','http://127.0.0.1/%7f','http://127.0.0.1/%3fadmin','http://127.0.0.1/%23admin']
        with patch('socket.getaddrinfo') as dns:
            for url in paths:
                with self.subTest(url=url),self.assertRaises(ValueError):Scope(self.scope()).check(url)
            dns.assert_not_called()
    def test_valid_scope_boundary_still_works(self):
        s=Scope(self.scope());self.assertEqual(s.check('http://127.0.0.1/public'),'127.0.0.1')
        for path in ['/admin','/admin/a','/%61dmin']:
            with self.assertRaises(PolicyError):s.check('http://127.0.0.1'+path)
    def test_invalid_upload_job_leaves_no_files(self):
        with tempfile.TemporaryDirectory() as t:
            jobs=Jobs(t)
            try:
                before=set(jobs.folder.iterdir())
                with self.assertRaises(PolicyError):jobs.submit({'archive_base64':base64.b64encode(b'PKjunk').decode(),'target':'http://127.0.0.1','scope':{}})
                self.assertEqual(set(jobs.folder.iterdir()),before)
            finally:jobs.close()
    def test_full_queue_rejects_before_persistence(self):
        with tempfile.TemporaryDirectory() as t:
            jobs=Jobs(t)
            try:
                before=set(jobs.folder.iterdir())
                with patch.object(jobs,'list',return_value=[{'status':'RUNNING'}]*10):
                    with self.assertRaises(PolicyError):jobs.submit({'source':'demo/source','preset':'offline'})
                self.assertEqual(set(jobs.folder.iterdir()),before)
            finally:jobs.close()
    def test_failed_enqueue_rolls_back_upload(self):
        with tempfile.TemporaryDirectory() as t:
            jobs=Jobs(t)
            try:
                before=set(jobs.folder.iterdir())
                with patch.object(jobs.tasks,'put',side_effect=RuntimeError('fixture failure')):
                    with self.assertRaises(RuntimeError):jobs.submit({'archive_base64':base64.b64encode(b'PKjunk').decode(),'preset':'offline'})
                self.assertEqual(set(jobs.folder.iterdir()),before)
            finally:jobs.close()
    def test_second_dashboard_cannot_interrupt_first(self):
        with tempfile.TemporaryDirectory() as t:
            jobs=Jobs(t)
            try:
                path=jobs.folder/('a'*32+'.json');path.write_text(json.dumps({'id':'a'*32,'status':'RUNNING','created':'test'}))
                with self.assertRaises(PolicyError):Jobs(t)
                self.assertEqual(json.loads(path.read_text())['status'],'RUNNING')
            finally:jobs.close()
    def test_corrupt_job_history_does_not_break_listing(self):
        with tempfile.TemporaryDirectory() as t:
            jobs=Jobs(t)
            try:
                (jobs.folder/'bad.json').write_text('[]');self.assertEqual(jobs.list(),[])
            finally:jobs.close()
    def test_resume_recovers_only_selected_record(self):
        with tempfile.TemporaryDirectory() as t:
            store=Store(t)
            try:
                for ident in ['a'*32,'b'*32]:store.save({'id':ident,'status':'RUNNING','events':[]})
                store.recover('a'*32);self.assertEqual(store.get('a'*32)['status'],'INTERRUPTED');self.assertEqual(store.get('b'*32)['status'],'RUNNING')
            finally:store.db.close()
    def test_broken_http_preflight_is_unreachable(self):
        with tempfile.TemporaryDirectory() as t,patch('secaudit.network.request',side_effect=http.client.BadStatusLine('untrusted response')):
            cfg=Config(target='http://127.0.0.1/',output=t,modules=['web'])
            result,_=doctor(cfg,Scope(self.scope()),check_target=True);self.assertFalse(result['ready']);self.assertTrue(any(r['status']=='UNREACHABLE' for r in result['components']))
    def test_invalid_zip_cli_has_no_traceback(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'bad.zip';p.write_bytes(b'PKjunk')
            result=subprocess.run([sys.executable,'-m','secaudit','scan','--archive',str(p),'--output',str(Path(t)/'out')],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(result.returncode,2);self.assertNotIn('Traceback',result.stderr)

class DashboardAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();sock=socket.socket();sock.bind(('127.0.0.1',0));cls.port=sock.getsockname()[1];sock.close()
        cls.p=subprocess.Popen([sys.executable,'-m','secaudit','dashboard','--port',str(cls.port),'--output',cls.tmp.name],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        cls.p.stdout.readline();cls.p.stdout.readline();password=cls.p.stdout.readline().strip().split(': ',1)[1];cls.auth='Basic '+base64.b64encode(('operator:'+password).encode()).decode()
        conn=http.client.HTTPConnection('127.0.0.1',cls.port);conn.request('GET','/api/bootstrap',headers={'Authorization':cls.auth});cls.csrf=json.loads(conn.getresponse().read())['csrf'];conn.close()
    @classmethod
    def tearDownClass(cls):cls.p.terminate();cls.p.communicate(timeout=5);cls.tmp.cleanup()
    def raw(self,headers,body=b'',path='/api/jobs'):
        with socket.create_connection(('127.0.0.1',self.port),timeout=3) as s:
            message=f'POST {path} HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: {self.auth}\r\nOrigin: http://127.0.0.1:{self.port}\r\nX-CSRF-Token: {self.csrf}\r\n'+headers+'\r\n'
            s.sendall(message.encode('latin-1')+body);s.shutdown(socket.SHUT_WR);return int(s.recv(4096).split(b' ',2)[1])
    def test_duplicate_length_rejected(self):self.assertEqual(self.raw('Content-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n',b'{}'),400)
    def test_truncated_body_rejected(self):self.assertEqual(self.raw('Content-Type: application/json\r\nContent-Length: 20\r\n',b'{}'),400)
    def test_chunked_body_rejected(self):self.assertEqual(self.raw('Content-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n',b'{}'),400)
    def test_deep_json_rejected(self):
        body=b'['*2000+b']'*2000;self.assertEqual(self.raw(f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n',body),400)
    def test_non_ascii_auth_fails_without_crash(self):
        conn=http.client.HTTPConnection('127.0.0.1',self.port);conn.request('GET','/',headers={'Authorization':'Basic \xff'});r=conn.getresponse();self.assertEqual(r.status,401);r.read();conn.close()
    def test_corrupt_run_returns_404(self):
        folder=Path(self.tmp.name)/('c'*32);folder.mkdir();(folder/'run.json').write_text('[]')
        conn=http.client.HTTPConnection('127.0.0.1',self.port);conn.request('GET','/api/runs/'+'c'*32,headers={'Authorization':self.auth});r=conn.getresponse();self.assertEqual(r.status,404);r.read();conn.close()
    def test_unauthenticated_browser_gets_challenge(self):
        conn=http.client.HTTPConnection('127.0.0.1',self.port);conn.request('GET','/');r=conn.getresponse();self.assertEqual(r.status,401);self.assertIn('Basic',r.getheader('WWW-Authenticate'));r.read();conn.close()

class ParserRegressionTests(unittest.TestCase):
    def test_invalid_html_link_does_not_abort_scan(self):
        from secaudit.network import scan_web
        scope=Scope({'authorization':'synthetic fixture','origins':['http://127.0.0.1/'],'exclusions':[],'environment':'lab','profiles':['passive'],'max_requests':2,'max_seconds':2,'allowed_ips':['127.0.0.1']})
        with patch('secaudit.network.request',return_value=(200,[('Content-Type','text/html')],b'<a href="http://[">broken</a>')):
            findings,assets,events=scan_web('http://127.0.0.1/',scope,lambda *a:None);self.assertEqual(len(assets),1);self.assertTrue(findings)
    def test_invalid_redirect_does_not_abort_scan(self):
        from secaudit.network import scan_web
        scope=Scope({'authorization':'synthetic fixture','origins':['http://127.0.0.1/'],'exclusions':[],'environment':'lab','profiles':['passive'],'max_requests':2,'max_seconds':2,'allowed_ips':['127.0.0.1']})
        with patch('secaudit.network.request',return_value=(302,[('Location','http://[')],b'')):
            _,assets,events=scan_web('http://127.0.0.1/',scope,lambda *a:None);self.assertEqual(len(assets),1);self.assertTrue(events)
    def test_invalid_dataset_is_not_published(self):
        from secaudit.datasets import build_snapshot
        with tempfile.TemporaryDirectory() as t:
            source=Path(t)/'input.json';source.write_text('[{"bad":"record"}]');dest=Path(t)/'data.json'
            with self.assertRaises(PolicyError):build_snapshot(source,dest,'urn:test','v1','2026-01-01T00:00:00Z')
            self.assertFalse(dest.exists());self.assertFalse(dest.with_suffix('.manifest.json').exists())
    def test_dataset_refuses_overwrite(self):
        from secaudit.datasets import build_snapshot
        with tempfile.TemporaryDirectory() as t:
            source=Path(t)/'input.json';source.write_text('[]');dest=Path(t)/'data.json';dest.write_text('preserve')
            with self.assertRaises(PolicyError):build_snapshot(source,dest,'urn:test','v1','2026-01-01T00:00:00Z')
            self.assertEqual(dest.read_text(),'preserve')
    def test_config_rejects_ambiguous_types(self):
        from secaudit.config import AIConfig
        for cfg in [Config(modules=[]),Config(ai=AIConfig(approved_ips='127.0.0.1')),Config(ai=AIConfig(model=[]))]:
            with self.assertRaises(PolicyError):cfg.validate()

class ConnectionBudgetTests(unittest.TestCase):
    def test_connection_slots_released_and_overflow_closed(self):
        from secaudit.dashboard import BoundedHTTPServer
        from http.server import BaseHTTPRequestHandler
        server=BoundedHTTPServer(('127.0.0.1',0),BaseHTTPRequestHandler)
        try:
            for _ in range(8):self.assertTrue(server.slots.acquire(blocking=False))
            with patch.object(server,'shutdown_request') as close:
                server.process_request(object(),('127.0.0.1',1));close.assert_called_once()
            for _ in range(8):server.slots.release()
            with patch('http.server.ThreadingHTTPServer.process_request',side_effect=RuntimeError('fixture')):
                with self.assertRaises(RuntimeError):server.process_request(object(),('127.0.0.1',1))
            for _ in range(8):self.assertTrue(server.slots.acquire(blocking=False))
            self.assertFalse(server.slots.acquire(blocking=False))
        finally:server.server_close()

class StrictFailureTests(unittest.TestCase):
    def run_case(self,modules,patch_code):
        with tempfile.TemporaryDirectory() as t:
            (Path(t)/'preflight_report.txt').write_text('synthetic preflight')
            script='''import sys
from unittest.mock import patch
from secaudit.cli import scan
from secaudit.config import Config
from secaudit.models import Finding
cfg=Config(source='demo/source',output=sys.argv[1],modules=MODULES,strict=True,advisory_dataset='fixture.json')
ready={'ready':True,'components':[{'component':n,'status':'READY'} for n in MODULES]}
with patch('secaudit.cli.doctor',return_value=(ready,None)), PATCHCODE:
 raise SystemExit(scan(cfg))
'''.replace('MODULES',repr(modules)).replace('PATCHCODE',patch_code)
            p=subprocess.run([sys.executable,'-c',script,t],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(p.returncode,1,p.stderr);result=json.loads(p.stdout);self.assertEqual(result['status'],'FAILED');return result
    def test_required_dataset_runtime_failure_fails_scan(self):
        self.run_case(['dependencies'],"patch('secaudit.datasets.Dataset',side_effect=ValueError('fixture failure'))")
    def test_prior_external_findings_survive_next_scanner_failure(self):
        result=self.run_case(['gitleaks','semgrep'],"patch('secaudit.adapters.execute',side_effect=[([Finding('TEST','Fixture','a.py','Synthetic','Review')],None),ValueError('fixture failure')])")
        self.assertEqual(result['findings'],1)
