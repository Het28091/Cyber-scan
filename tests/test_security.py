import json,os,socket,stat,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from secaudit.security import *
from secaudit.config import Config,AIConfig
from secaudit.models import Finding,dedup
from secaudit.preflight import doctor
from secaudit.reporting import reports
from secaudit.store import Store
ROOT=Path(__file__).resolve().parents[1]
def scope(): return Scope({'authorization':'synthetic lab authorization','origins':['http://127.0.0.1:3000/allowed'],'exclusions':['http://127.0.0.1:3000/allowed/admin'],'environment':'lab','profiles':['passive'],'max_requests':10,'max_seconds':10,'allowed_ips':['127.0.0.1']})
class SecurityTests(unittest.TestCase):
    def test_scope_paths_and_exclusion(self):
        s=scope();self.assertEqual(s.check('http://127.0.0.1:3000/allowed/a'),'127.0.0.1')
        for suffix in ['allowedness','allowed/admin/x','allowed/../admin','allowed/%2e%2e/admin','allowed%2fadmin','allowed/%252e%252e/']:
            with self.subTest(suffix=suffix),self.assertRaises(PolicyError): s.check('http://127.0.0.1:3000/'+suffix)
        for url in ['http://user:pass@127.0.0.1:3000/allowed','http://127.0.0.1:3001/allowed']:
            with self.assertRaises(PolicyError): s.check(url)
    def test_dns_rebinding(self):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',3000))]):
            with self.assertRaises(PolicyError): scope().check('http://127.0.0.1:3000/allowed')
    def test_ipv6(self): self.assertEqual(canonical('http://[::1]:3000/a')[0],'http://[::1]:3000')
    def test_kernel_offline_network_block(self):
        script='from secaudit.security import deny_network; import socket; deny_network();\ntry: socket.socket()\nexcept PermissionError: raise SystemExit(0)\nraise SystemExit(1)'
        p=subprocess.run([sys.executable,'-c',script],capture_output=True,cwd=ROOT);self.assertEqual(p.returncode,0,p.stderr.decode())
    def test_api_blocked_offline(self):
        with self.assertRaises(PolicyError): Config(ai=AIConfig(enabled=True,provider='openai-compatible')).validate()
    def test_invalid_config(self):
        for c in [Config(modules=['unknown']),Config(timeout=-1),Config(max_files=True),Config(ai=AIConfig(concurrency=4))]:
            with self.assertRaises(PolicyError): c.validate()
    def test_redaction(self):
        s=redact('password="hidden-password" token=abc123 foo=a@example.org\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----')
        for v in ('hidden-password','abc123','a@example.org','\nabc\n'): self.assertNotIn(v,s)
    def test_archive_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.zip'
            with zipfile.ZipFile(p,'w') as z: z.writestr('../outside','bad')
            with self.assertRaises(PolicyError): extract_zip(p,Path(t)/'out')
            self.assertFalse((Path(t)/'out').exists())
    def test_archive_rejects_symlink_and_limits(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.zip';i=zipfile.ZipInfo('link');i.external_attr=(stat.S_IFLNK|0o777)<<16
            with zipfile.ZipFile(p,'w') as z: z.writestr(i,'/etc/passwd')
            with self.assertRaises(PolicyError): extract_zip(p,Path(t)/'out')
            with zipfile.ZipFile(p,'w') as z: z.writestr('data','A'*100)
            with self.assertRaises(PolicyError): extract_zip(p,Path(t)/'out',max_bytes=10)
    def test_archive_valid(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.zip'
            with zipfile.ZipFile(p,'w') as z: z.writestr('source/a.py','x=1')
            out=extract_zip(p,Path(t)/'out');self.assertEqual((out/'source/a.py').read_text(),'x=1')
    def test_missing_modules_preflight(self):
        with tempfile.TemporaryDirectory() as t:
            cfg=Config(source=str(ROOT/'demo/source'),output=t,modules=['dependencies','gitleaks'])
            r,_=doctor(cfg);self.assertTrue(r['ready']);self.assertIn('DATA_MISSING',[x['status'] for x in r['components']])
            cfg.strict=True;r,_=doctor(cfg);self.assertFalse(r['ready'])
    def test_dedup_preserves_evidence(self):
        a=Finding('rule','A','a.py','x','y',evidence=['one']);b=Finding('rule','A','a.py','x','y',evidence=['two'],scanner='second')
        out=dedup([a,b]);self.assertEqual(len(out),1);self.assertEqual(out[0].evidence,['one','two']);self.assertEqual(out[0].provenance[0]['scanner'],'second')
    def test_csv_formula(self):
        for s in ['=1+1','+CMD',' @SUM(A1)','\t=1']: self.assertTrue(csv_safe(s).startswith("'"))
    def test_reports_escape_html_and_redact(self):
        with tempfile.TemporaryDirectory() as t:
            f=Finding('test','<script>alert(1)</script>','=formula','password="hidden-password"','fix').to_dict()
            reports(t,{'id':'demo','mode':'offline','status':'PARTIAL','findings':[f],'coverage':[],'assets':[],'components':[],'events':[]})
            self.assertNotIn('<script>',(Path(t)/'technical.html').read_text());self.assertIn('&lt;script&gt;',(Path(t)/'technical.html').read_text())
            self.assertNotIn('hidden-password',(Path(t)/'findings.json').read_text());self.assertIn("'=formula",(Path(t)/'findings.csv').read_text())
    def test_atomic_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';atomic(p,'test');self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
    def test_recovery_preserves_partial(self):
        with tempfile.TemporaryDirectory() as t:
            s=Store(t);s.save({'id':'abc','status':'RUNNING','events':[],'findings':[{'id':'one'}]});s.recover();r=s.get('abc');self.assertEqual(r['status'],'INTERRUPTED');self.assertEqual(r['findings'],[{'id':'one'}]);s.db.close()
