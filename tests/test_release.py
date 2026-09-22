import base64,hashlib,http.client,json,os,socket,subprocess,sys,tempfile,time,unittest
from datetime import datetime,timezone,timedelta
from pathlib import Path
from unittest.mock import patch
from secaudit.datasets import Dataset,build_snapshot
from secaudit.adapters import parse,bounded,probe
from secaudit.security import PolicyError
from secaudit.config import Config
from secaudit.preflight import doctor
ROOT=Path(__file__).resolve().parents[1]

class ReleaseTests(unittest.TestCase):
    def snapshot(self,folder,age=0):
        source=Path(folder)/'input.json';source.write_text(json.dumps([{'id':'DEMO-001','ecosystem':'PyPI','name':'flask','affected_versions':['0.1'],'summary':'Synthetic fixture, not a real vulnerability','source':'urn:secaudit:test'}]))
        dest=Path(folder)/'advisories.json';build_snapshot(source,dest,'urn:secaudit:test','fixture-1',(datetime.now(timezone.utc)-timedelta(days=age)).isoformat());return dest
    def test_dataset_integrity_and_exact_matching(self):
        with tempfile.TemporaryDirectory() as t:
            p=self.snapshot(t);ds=Dataset(p);self.assertEqual(len(ds.scan([{'name':'Flask','version':'0.1','purl':'pkg:pypi/flask@0.1'}])),1)
            self.assertEqual(ds.scan([{'name':'Flask','version':'0.2','purl':'pkg:pypi/flask@0.2'}]),[])
            p.write_text('[]')
            with self.assertRaises(PolicyError):Dataset(p)
    def test_stale_dataset_block_and_warning(self):
        with tempfile.TemporaryDirectory() as t:
            p=self.snapshot(t,60);self.assertTrue(Dataset(p).stale)
            with self.assertRaises(PolicyError):Dataset(p,30,True)
    def test_dependency_cli_regression(self):
        with tempfile.TemporaryDirectory() as t:
            p=self.snapshot(t);source=Path(t)/'source';source.mkdir();(source/'requirements.txt').write_text('flask==0.1\n')
            cfg=Path(t)/'config.json';cfg.write_text(json.dumps({'source':str(source),'output':str(Path(t)/'runs'),'modules':['dependencies'],'advisory_dataset':str(p)}))
            result=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(cfg)],capture_output=True,text=True,cwd=ROOT)
            self.assertEqual(result.returncode,0,result.stderr);summary=json.loads(result.stdout);self.assertEqual(summary['findings'],1)
            run=json.loads((Path(summary['reports'])/'run.json').read_text());self.assertEqual(run['coverage'][0]['status'],'PARTIAL');self.assertTrue(run['findings'][0]['mappings'])
    def test_external_missing_cli_regression(self):
        with tempfile.TemporaryDirectory() as t:
            cfg=Path(t)/'config.json';cfg.write_text(json.dumps({'source':str(ROOT/'demo/source'),'output':str(Path(t)/'runs'),'modules':['gitleaks'],'scanners':{'gitleaks':{'executable':'/missing/tool'}}}))
            result=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(cfg)],capture_output=True,text=True,cwd=ROOT)
            self.assertEqual(result.returncode,0,result.stderr)
            run=json.loads((Path(json.loads(result.stdout)['reports'])/'run.json').read_text());self.assertEqual(run['coverage'][0]['status'],'NOT TESTED')
    def test_adapter_discards_secrets(self):
        data=[{'RuleID':'key','File':'/input/a.py','StartLine':2,'Secret':'never-store-this','Match':'never-store-this'}]
        fs,_=parse('gitleaks',json.dumps(data),'8.test');self.assertNotIn('never-store-this',json.dumps([f.to_dict() for f in fs]))
    def test_malformed_adapter_output(self):
        for name,data in [('gitleaks',{}),('semgrep',{'results':[],'errors':['bad']}),('trivy',{}),('syft',{})]:
            with self.assertRaises(PolicyError):parse(name,json.dumps(data),'test')
    def test_process_timeout_and_output_limit(self):
        with self.assertRaises(PolicyError):bounded([sys.executable,'-c','import time;time.sleep(5)'],.1)
        with self.assertRaises(PolicyError):bounded([sys.executable,'-c','print("x"*100000)'],2,1000)
    def test_isolation_failure_blocks_external_tool(self):
        with patch('secaudit.adapters.bounded',return_value=(1,b'')),patch('secaudit.adapters.sandbox_command',return_value=['sandbox']),patch('shutil.which',return_value='/usr/bin/tool'):
            with self.assertRaisesRegex(PolicyError,'POLICY_BLOCKED'):probe('gitleaks',{})
    def test_pdf_and_framework_exports(self):
        with tempfile.TemporaryDirectory() as t:
            result=subprocess.run([sys.executable,'-m','secaudit','scan','--source','demo/source','--output',t],capture_output=True,text=True,cwd=ROOT)
            self.assertEqual(result.returncode,0,result.stderr);d=Path(json.loads(result.stdout)['reports'])
            for name in ['technical.pdf','executive.pdf']:self.assertTrue((d/name).read_bytes().startswith(b'%PDF-'))
            self.assertIn('NIST CSF',(d/'framework-mappings.csv').read_text())
    def test_queue_recovery(self):
        from secaudit.jobs import Jobs
        with tempfile.TemporaryDirectory() as t:
            folder=Path(t)/'.jobs';folder.mkdir();p=folder/('a'*32+'.json');p.write_text(json.dumps({'id':'a'*32,'created':'2026-01-01','status':'RUNNING'}))
            jobs=Jobs(t)
            try:self.assertEqual(jobs.list()[0]['status'],'INTERRUPTED')
            finally:jobs.close()
    def test_dashboard_csrf_submission_and_reports(self):
        with tempfile.TemporaryDirectory() as t:
            sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
            process=subprocess.Popen([sys.executable,'-m','secaudit','dashboard','--output',t,'--port',str(port)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                process.stdout.readline();process.stdout.readline();password=process.stdout.readline().strip().split(': ',1)[1]
                auth='Basic '+base64.b64encode(('operator:'+password).encode()).decode()
                def request(method,path,payload=None,csrf=None):
                    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=10);headers={'Authorization':auth,'Content-Type':'application/json','Origin':f'http://127.0.0.1:{port}'}
                    if csrf:headers['X-CSRF-Token']=csrf
                    conn.request(method,path,body=json.dumps(payload) if payload is not None else None,headers=headers);r=conn.getresponse();data=r.read();status=r.status;conn.close();return status,data
                _,body=request('GET','/api/bootstrap');csrf=json.loads(body)['csrf']
                self.assertEqual(request('POST','/api/jobs',{'source':'demo/source'})[0],403)
                status,body=request('POST','/api/jobs',{'source':'demo/source'},csrf);self.assertEqual(status,202,body);ident=json.loads(body)['id']
                for _ in range(100):
                    _,body=request('GET','/api/jobs');job=json.loads(body)[0]
                    if job['status'] not in ('QUEUED','RUNNING'):break
                    time.sleep(.05)
                self.assertEqual(job['status'],'COMPLETED',job)
                status,body=request('GET','/api/runs/'+ident);self.assertEqual(status,200);self.assertIn('technical.pdf',json.loads(body)['available_reports'])
                status,body=request('GET','/reports/'+ident+'/technical.pdf');self.assertEqual(status,200);self.assertTrue(body.startswith(b'%PDF-'))
                self.assertEqual(request('GET','/reports/'+ident+'/../../secret')[0],404)
            finally:process.terminate();process.communicate(timeout=5)

if __name__=='__main__':unittest.main()
