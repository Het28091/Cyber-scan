"""Separate Linux mode journeys using owned fixtures, never a real API or target."""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

from secaudit.cli import scan
from secaudit.config import Config,AIConfig
from secaudit.models import now
from secaudit.security import write_json


def result(output):
    path=max(Path(output).glob('*/run.json'),key=lambda p:p.stat().st_mtime)
    run=json.loads(path.read_text())
    assert all((path.parent/p).read_bytes().startswith(b'%PDF-') for p in ['technical.pdf','executive.pdf'])
    return run


def main():
    rows=[]
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        for name,text,expected in [
            ('final-root','FROM base\nUSER app\nUSER root\n',{'DOCKER-USER'}),
            ('inherited-user','FROM base AS build\nUSER app\nFROM build\n',set())]:
            source=root/name;source.mkdir();(source/'Dockerfile').write_text(text)
            output=root/(name+'-runs')
            # Deny networking before preflight; the actual CLI inherits the filter.
            script="""import socket,sys
from secaudit.security import deny_network
from secaudit.cli import scan
from secaudit.config import Config
deny_network()
try: socket.socket()
except PermissionError: pass
else: raise AssertionError('network isolation missing')
raise SystemExit(scan(Config(source=sys.argv[1],output=sys.argv[2],modules=['config'],pdf_required=True).validate()))
"""
            subprocess.run([sys.executable,'-c',script,str(source),str(output)],check=True,timeout=60)
            run=result(output)
            assert {f['rule'] for f in run['findings']}==expected and not run['ai_usage']['enabled']
            rows.append(dict(mode='offline',case=name,status='PASS',network_denied=True,finding_count=len(run['findings'])))

        requests=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_HEAD(self):self.do_GET()
            def do_GET(self):
                requests.append((self.command,self.path))
                self.send_response(200)
                self.send_header('Content-Security-Policy', '' if self.path=='/empty' else "default-src 'none'")
                self.send_header('X-Content-Type-Options','' if self.path=='/empty' else 'nosniff')
                self.send_header('Content-Length','0');self.end_headers()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            for page,expected in [('empty',2),('valid',0)]:
                target=f'http://127.0.0.1:{server.server_port}/{page}'
                scope=root/'scope.json'
                write_json(scope,dict(authorization='owned mode fixture',origins=[target],exclusions=[],environment='test',profiles=['passive'],allowed_ips=['127.0.0.1'],max_requests=1,max_seconds=5))
                output=root/('web-'+page)
                assert scan(Config(mode='internet',target=target,scope=str(scope),output=str(output),modules=['web'],pdf_required=True).validate())==0
                run=result(output)
                assert len(run['findings'])==expected and not run['ai_usage']['enabled']
                rows.append(dict(mode='internet-no-ai',case=page,status='PASS',finding_count=expected))
            assert requests==[('HEAD','/empty'),('GET','/empty'),('HEAD','/valid'),('GET','/valid')]
        finally:server.shutdown();server.server_close();worker.join()

        source=root/'ai-source';source.mkdir();(source/'owned.py').write_text('eval(user_input)\n')
        for reason,expected_code in [('stop',0),('length',1)]:
            calls=[]
            def transport(url,scope,method,body,headers,*args):
                calls.append(url)
                if url.endswith('/models'):data={'data':[{'id':'fixture'}]}
                else:
                    payload=json.loads(body);metadata=json.loads(payload['messages'][1]['content'])
                    assert all(set(item)=={'id','rule','severity'} for item in metadata)
                    assert 'owned.py' not in body.decode() and 'user_input' not in body.decode()
                    data={'choices':[{'finish_reason':reason,'message':{'content':json.dumps({'suggestions':[{'id':metadata[0]['id'],'text':'Review input handling.'}]})}}]}
                return 200,[],json.dumps(data).encode()
            output=root/('ai-'+reason)
            cfg=Config(mode='connected-ai',source=str(source),output=str(output),modules=['source'],pdf_required=True,
                ai=AIConfig(enabled=True,provider='openai-compatible',endpoint='https://owned.example.invalid/v1',model='fixture',
                            approved_ips=['192.0.2.1'],failure_policy='required',response_format='json_object'))
            with patch.dict(os.environ,{'SECAUDIT_EXPERIMENTAL_AI':'1','SECAUDIT_API_KEY':'synthetic-fixture-key'}),patch('secaudit.ai.request',side_effect=transport):
                code=scan(cfg.validate())
            run=result(output)
            assert code==expected_code and len(calls)==2 and len(run['findings'])==1
            assert run['status']==('FAILED' if expected_code else 'COMPLETED_WITH_LIMITATIONS')
            if expected_code:assert not run['ai_suggestions']
            rows.append(dict(mode='connected-ai',case=reason,status='PASS',provider='FIXTURE ONLY',scan_status=run['status'],deterministic_findings_preserved=True))
    evidence=dict(source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),timestamp=now(),status='PASS',cases=rows,
                  limitations=['Owned regression fixtures only; not universal detection accuracy.','Real API inference and free-only account acceptance remain NOT TESTED.'])
    write_json('artifacts/checkpoints/mode-quality/journeys.json',evidence)
    print(json.dumps(evidence,indent=2))


if __name__=='__main__':main()
