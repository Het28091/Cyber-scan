"""Linux-only, prepared Chromium/Bubblewrap acceptance against an owned fixture."""
import argparse
import json
import subprocess
import sys
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from secaudit.security import PolicyError,write_json


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--executable',required=True)
    parser.add_argument('--evidence',required=True)
    args=parser.parse_args()
    from secaudit.browser_resource import service_command
    unit='secaudit-budget-fixture-'+uuid.uuid4().hex
    # Real positive startup followed by a deliberate allocation over the cgroup
    # limit. Only owned Python code runs; swap is denied and all child tasks are
    # included in the same kernel memory budget.
    probe=service_command([sys.executable,'-c',"print('budget-probe-started',flush=True); data=bytearray(2*1024**3); print('budget-bypass',flush=True)"],15,unit)
    try:
        checked=subprocess.run(probe,capture_output=True,text=True,timeout=20)
        if checked.returncode==0 or 'budget-probe-started' not in checked.stdout or 'budget-bypass' in checked.stdout:
            raise PolicyError('Real renderer memory-budget control failed')
    finally:subprocess.run(['systemctl','--user','stop',unit],capture_output=True,timeout=3)
    visits=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            visits.append(self.path)
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            origin=f'http://127.0.0.1:{self.server.server_port}'
            self.wfile.write(('<html><body><form><input type="password"></form><a href="/next">Next</a>'
                '<script>document.write("<form></form>");fetch("'+origin+'/leak")</script>'
                '<img src="'+origin+'/leak"></body></html>').encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);origin=f'http://127.0.0.1:{server.server_port}'
            write_json(root/'scope.json',dict(authorization='owned browser snapshot fixture',origins=[origin],exclusions=[],environment='lab',profiles=['passive','bounded'],max_requests=1,max_seconds=30,allowed_ips=['127.0.0.1']))
            write_json(root/'config.json',dict(source='',target=origin,scope=str(root/'scope.json'),output=str(root/'runs'),modules=['target_workflow'],strict=True,target_workflow={'browser':{'urls':[origin],'executable':args.executable}}))
            result=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(root/'config.json')],capture_output=True,text=True,timeout=90)
            if result.returncode:raise PolicyError('Target browser acceptance failed; sandbox/runtime unavailable or fixture failed')
            run=json.loads((Path(json.loads(result.stdout)['reports'])/'run.json').read_text())
            browser=run['assets'][0].get('browser',{})
            if visits!=['/'] or browser.get('forms')!=1 or browser.get('password_inputs')!=1 or browser.get('links')!=1 or browser.get('javascript') is not False or browser.get('browser_network') is not False:
                raise PolicyError('Target browser containment or rendering control failed')
            write_json(args.evidence,{'status':'PASS','checks':['verified kernel memory/process/swap limits','oversized allocation terminated','pinned single fetch','real offline Chromium rendering','script-disabled positive control','no subresource network request'],'browser':browser,'limitation':'Static snapshot only; not interactive application browser acceptance'})
    finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,subprocess.TimeoutExpired):
        print('Target browser acceptance failed. Review the prepared Linux runtime and sandbox.',file=sys.stderr);raise SystemExit(1)
