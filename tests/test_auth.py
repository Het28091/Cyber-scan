import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from secaudit.auth import StaticAuth
from secaudit.network import request, scan_web
from secaudit.security import Scope, PolicyError, write_json


def data(origin='http://127.0.0.1:9876'):
    return dict(authorization='owned auth fixture', origins=[origin+'/'], exclusions=[origin+'/private/logout'],
                environment='lab', profiles=['passive'], max_requests=8, max_seconds=10, allowed_ips=['127.0.0.1'],
                authentication=dict(type='bearer',env='SECAUDIT_TARGET_TEST',origin=origin,paths=['/private']))


class AuthTests(unittest.TestCase):
    def test_rejects_unsafe_auth_configuration(self):
        cases=[None,{},dict(data()['authentication'],token='literal'),dict(data()['authentication'],type='basic'),
               dict(data()['authentication'],env='HOME'),dict(data()['authentication'],origin='http://remote.example'),
               dict(data()['authentication'],origin='https://remote.example/path'),
               dict(data()['authentication'],paths=[]),dict(data()['authentication'],paths=['//bad']),
               dict(data()['authentication'],paths=['/x?secret=value']),dict(data()['authentication'],paths=['relative'])]
        for value in cases:
            with self.subTest(value=value),self.assertRaises((PolicyError,ValueError)):
                StaticAuth(value)
        with self.assertRaises(PolicyError):
            Scope(dict(data(),authentication=dict(data()['authentication'],origin='https://other.example')))

    def test_no_credentials_outside_boundaries(self):
        auth=StaticAuth(data()['authentication'])
        for url in ('http://127.0.0.1:9876/public','http://127.0.0.1:9876/private-other','http://127.0.0.1:9877/private','https://other.example/private'):
            with self.subTest(url=url): self.assertEqual(auth.headers(url),{})

    def test_missing_or_injected_credential_blocks_before_connect(self):
        scope=Scope(data())
        for secret in ('','short','token123\r\nX-Evil: yes','token123\x7f','token with spaces','x'*8193):
            with patch.dict(os.environ,{'SECAUDIT_TARGET_TEST':secret}),patch('secaudit.network.PinnedHTTP') as transport:
                with self.assertRaises(PolicyError):request('http://127.0.0.1:9876/private',scope)
                transport.assert_not_called()
        with patch.dict(os.environ,{'SECAUDIT_TARGET_TEST':'synthetic123'}),patch('secaudit.network.PinnedHTTP') as transport:
            for kwargs in ({'method':'POST'},{'headers':{'Authorization':'other'}},{'headers':{'Cookie':'other'}}):
                with self.assertRaises(PolicyError):request('http://127.0.0.1:9876/private',scope,**kwargs)
            with self.assertRaises(PolicyError):request('http://127.0.0.1:9876/private/logout',scope)
            transport.assert_not_called()

    def test_cookie_validation_and_evidence_redaction(self):
        auth=StaticAuth(dict(data()['authentication'],type='cookie'))
        for secret in ('badcookie','session=short','session=bad value123','session=12345678\n','session="quotedvalue"'):
            with patch.dict(os.environ,{'SECAUDIT_TARGET_TEST':secret}),self.assertRaises(PolicyError):
                auth.headers('http://127.0.0.1:9876/private')
        with patch.dict(os.environ,{'SECAUDIT_TARGET_TEST':'session=Abcde12345; csrf=Xyz9876543'}):
            self.assertIn('Cookie',auth.headers('http://127.0.0.1:9876/private'))
            with tempfile.TemporaryDirectory() as t:
                path=Path(t)/'evidence.json';write_json(path,{'asset':'/reflected/Abcde12345','evidence':'Xyz9876543'})
                self.assertNotIn('Abcde12345',path.read_text());self.assertNotIn('Xyz9876543',path.read_text())

    def test_live_loopback_redirect_and_auth_rejection(self):
        observations=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_HEAD(self): self.do_GET()
            def do_GET(self):
                observations.append((self.path,self.headers.get('Authorization'),self.headers.get('Cookie')))
                if self.path.startswith('/private') and self.headers.get('Authorization')!='Bearer fixture-secret-98765' and self.headers.get('Cookie')!='session=CookieValue9876':
                    self.send_response(401);body=b''
                elif self.path=='/private/start':
                    self.send_response(302);self.send_header('Location','/public');body=b''
                elif self.path=='/private/reject':
                    self.send_response(401);body=b''
                else:
                    self.send_response(200);body=b'<a href="/private/logout">logout</a>'
                    self.send_header('Content-Type','text/html')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            origin=f'http://127.0.0.1:{server.server_port}';scope=Scope(data(origin))
            with patch.dict(os.environ,{'SECAUDIT_TARGET_TEST':'fixture-secret-98765'}):
                _,assets,_=scan_web(origin+'/private/start',scope,lambda *_:None)
                self.assertEqual(len(assets),2)
                self.assertEqual(observations[0][1],'Bearer fixture-secret-98765')
                self.assertIsNone(observations[1][1]);self.assertFalse(any(x[0].endswith('logout') for x in observations))
                findings,assets,events=scan_web(origin+'/private/reject',scope,lambda *_:None)
                self.assertFalse(findings);self.assertEqual(assets[0]['status'],401)
                self.assertTrue(any('AUTHENTICATION_REJECTED' in e for e in events))
            observations.clear()
            scope=Scope(dict(data(origin),authentication=dict(data(origin)['authentication'],type='cookie')))
            with patch.dict(os.environ,{'SECAUDIT_TARGET_TEST':'session=CookieValue9876'}):
                request(origin+'/private',scope)
                self.assertEqual(observations[0][2],'session=CookieValue9876')
            with tempfile.TemporaryDirectory() as temp:
                root=Path(__file__).resolve().parents[1]
                scopefile=Path(temp)/'scope.json';scopefile.write_text(json.dumps(data(origin)))
                cfg=Path(temp)/'config.json';cfg.write_text(json.dumps(dict(mode='offline',target=origin+'/private',scope=str(scopefile),output=temp+'/runs',modules=['web'],strict=True)))
                env=dict(os.environ,SECAUDIT_TARGET_TEST='fixture-secret-98765')
                result=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(cfg)],cwd=root,env=env,capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stderr)
                report=Path(json.loads(result.stdout)['reports'])/'run.json'
                saved=report.read_text();self.assertNotIn('fixture-secret-98765',saved)
                self.assertTrue(json.loads(saved)['network_policy']['static_authentication'])
                env['SECAUDIT_TARGET_TEST']='rejected-secret-123'
                result=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(cfg)],cwd=root,env=env,capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,2)
                self.assertNotIn('rejected-secret-123',result.stderr)
        finally:
            server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
