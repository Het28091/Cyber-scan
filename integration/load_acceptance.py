"""Full owned source scan and real queue drain; timings are observations, not SLAs."""
import json
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from secaudit.jobs import Jobs

ROOT=Path(__file__).resolve().parents[1]


def target_measurement(root):
    visits=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def headers(self):
            self.send_response(200);self.send_header('Content-Type','text/html')
            self.send_header('Content-Security-Policy',"default-src 'none'")
            self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
        def do_HEAD(self):visits.append(('HEAD',self.path));self.headers()
        def do_GET(self):
            visits.append(('GET',self.path));self.headers()
            self.wfile.write((''.join(f'<a href="/page/{n}">Owned</a>' for n in range(1,20))).encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        origin=f'http://127.0.0.1:{server.server_port}'
        scope=root/'scope.json';scope.write_text(json.dumps({'authorization':'owned load fixture','origins':[origin],
            'exclusions':[],'environment':'lab','profiles':['passive'],'max_requests':20,'max_seconds':30,'allowed_ips':['127.0.0.1']}))
        cfg=root/'target.json';cfg.write_text(json.dumps({'mode':'offline','source':'','target':origin,
            'scope':str(scope),'output':str(root/'target-runs'),'modules':['web']}))
        started=time.monotonic()
        process=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(cfg)],cwd=ROOT,capture_output=True,text=True,timeout=60)
        summary=json.loads(process.stdout)
        run=json.loads((Path(summary['reports'])/'run.json').read_text())
        gets=[path for method,path in visits if method=='GET']
        passed=process.returncode==0 and len(gets)==len(set(gets))==20 and len(run['assets'])==20
        return {'name':'twenty owned HTTP pages','status':'PASS' if passed else 'FAIL',
            'seconds':round(time.monotonic()-started,3),'get_requests':len(gets),
            'preflight_head_requests':sum(method=='HEAD' for method,_ in visits),'assets':len(run['assets'])}
    finally:server.shutdown();server.server_close();thread.join(timeout=3)


def main():
    result={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'python':platform.python_version(),'platform':platform.platform(),'checks':[]}
    with tempfile.TemporaryDirectory(prefix='secaudit-load-') as temp:
        root=Path(temp);source=root/'source';source.mkdir()
        for n in range(4999):(source/f'clean{n}.py').write_text('value = 1\n')
        started=time.monotonic()
        process=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(ROOT/'config/offline.json'),
            '--source',str(source),'--output',str(root/'runs')],cwd=ROOT,capture_output=True,text=True,timeout=90)
        summary=json.loads(process.stdout)
        run=json.loads((Path(summary['reports'])/'run.json').read_text())
        result['checks'].append({'name':'4999-file full assessment','status':summary['status'],
            'seconds':round(time.monotonic()-started,3),'assets':len(run['assets']),
            'report_bytes':sum(p.stat().st_size for p in Path(summary['reports']).iterdir() if p.is_file()),
            'returncode':process.returncode})
        target=target_measurement(root);result['checks'].append(target)
        small=root/'small';small.mkdir();(small/'owned.py').write_text('value = 1\n')
        jobs=Jobs(root/'queue');started=time.monotonic()
        try:
            admitted=[jobs.submit({'source':str(small),'preset':'offline'})['id'] for _ in range(10)]
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                records=[jobs.detail(ident) for ident in admitted]
                if all(j['status'] not in ('QUEUED','RUNNING') for j in records):break
                time.sleep(.05)
            result['checks'].append({'name':'ten real queued source assessments',
                'seconds':round(time.monotonic()-started,3),'statuses':[j['status'] for j in records]})
        finally:jobs.close()
        result['peak_child_rss_kib']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        passed=process.returncode==0 and len(run['assets'])==4999 and target['status']=='PASS' and all(j['status']=='COMPLETED' for j in records)
    result.update(status='PASS' if passed else 'FAIL',limitations=['Owned clean Python files only; not a universal scanner performance budget',
        'Default 60-second scan timeout unchanged; owner hardware/budget approval pending',
        'RSS is cumulative child maximum, not per-job profiling; no AI or external target traffic'])
    path=ROOT/'artifacts/checkpoints/independent/load.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n')
    print('::notice::Owned load evidence: '+json.dumps(result))
    if not passed:raise SystemExit(1)


if __name__=='__main__':main()
