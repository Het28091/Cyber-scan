import base64,json,secrets,mimetypes,re,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .security import PolicyError,redact
from .jobs import Jobs
from . import __version__

class BoundedHTTPServer(ThreadingHTTPServer):
    """Cap concurrent connections, including unauthenticated slow clients."""
    daemon_threads=True
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(*args,**kwargs)
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request);return
        try: super().process_request(request,client_address)
        except BaseException:
            self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try: super().process_request_thread(request,client_address)
        finally: self.slots.release()

DOWNLOADS={'inventory.json','technical.html','technical.md','technical.pdf','executive.html','executive.pdf','findings.json','findings.csv','findings.sarif','coverage.csv','framework-mappings.csv','sbom.cdx.json','external-sbom.cdx.json','assets.json','preflight_report.json','preflight_report.txt','remediation-retest.md','run.json','audit.jsonl','ai-suggestions.json'}
def serve(root,port=8765):
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    static=Path(__file__).parent/'static';jobs=Jobs(root)
    token=secrets.token_urlsafe(24);csrf=secrets.token_urlsafe(32)
    expected='Basic '+base64.b64encode(('operator:'+token).encode()).decode()
    def run(ident):
        if not re.fullmatch('[a-f0-9]{32}',ident): raise PolicyError('invalid run ID')
        # Output is operator-owned. These checks reject accidents, not same-UID races.
        folder=root/ident
        if folder.is_symlink(): raise PolicyError('symlink output refused')
        path=folder/'run.json'
        if not path.exists(): path=folder/'partial.json'
        if path.is_symlink() or path.stat().st_size>10_000_000: raise PolicyError('run unavailable')
        result=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(result,dict) or any(not isinstance(result.get(k),list) for k in ('findings','assets','coverage')): raise PolicyError('invalid saved run')
        result['available_reports']=[n for n in sorted(DOWNLOADS) if (folder/n).is_file() and not (folder/n).is_symlink()]
        return result
    class Handler(BaseHTTPRequestHandler):
        def setup(self): super().setup();self.connection.settimeout(15)
        def log_message(self,*args): pass
        def authorized(self,mutation=False):
            if len(self.headers.get_all('Host',[]))!=1 or len(self.headers.get_all('Authorization',[]))>1:
                self.send_error(401);return False
            if self.headers.get('Host') not in (f'127.0.0.1:{port}',f'localhost:{port}'):
                self.send_error(403);return False
            if not secrets.compare_digest(self.headers.get('Authorization','').encode('utf-8'),expected.encode('ascii')):
                self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="Secaudit"');self.end_headers();return False
            if mutation and (any(len(self.headers.get_all(k,[]))!=1 for k in ('Origin','X-CSRF-Token')) or self.headers.get('Origin') not in (f'http://127.0.0.1:{port}',f'http://localhost:{port}') or not secrets.compare_digest(self.headers.get('X-CSRF-Token','').encode('utf-8'),csrf.encode('ascii'))):
                self.send_error(403);return False
            return True
        def send(self,data,kind='application/json',code=200,filename=None):
            if kind=='application/json': data=json.dumps(redact(data)).encode()
            if isinstance(data,str): data=data.encode('utf-8')
            self.send_response(code);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if filename: self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
            self.end_headers();self.wfile.write(data)
        def do_GET(self):
            if not self.authorized(): return
            try:
                path=urlsplit(self.path).path
                if path in ('/','/static/app.js','/static/style.css'):
                    name='index.html' if path=='/' else path.split('/')[-1]
                    kind={'index.html':'text/html; charset=utf-8','app.js':'text/javascript; charset=utf-8','style.css':'text/css; charset=utf-8'}[name]
                    self.send((static/name).read_bytes(),kind);return
                if path=='/api/bootstrap': self.send({'csrf':csrf,'version':__version__,'presets':['internet','offline'],'network':'Local dashboard','max_upload_bytes':10_000_000});return
                if path=='/api/jobs': self.send(jobs.list());return
                if path=='/api/runs':
                    rows=[]
                    for p in root.iterdir():
                        if not p.is_dir() or not re.fullmatch('[a-f0-9]{32}',p.name): continue
                        try:
                            r=run(p.name);rows.append({k:r.get(k) for k in ('id','status','started','finished','mode','coverage')}|{'findings':len(r['findings']),'assets':len(r['assets']),'high':sum(f['severity'] in ('CRITICAL','HIGH') for f in r['findings'])})
                        except (ValueError,OSError,KeyError,TypeError,RecursionError): pass
                    self.send(sorted(rows,key=lambda r:r.get('started',''),reverse=True)[:200]);return
                match=re.fullmatch(r'/api/runs/([a-f0-9]{32})',path)
                if match: self.send(run(match[1]));return
                match=re.fullmatch(r'/reports/([a-f0-9]{32})/([a-zA-Z0-9.-]+)',path)
                if match and match[2] in DOWNLOADS:
                    run(match[1]);p=root/match[1]/match[2]
                    if p.is_symlink() or p.stat().st_size>30_000_000: raise PolicyError('report unavailable')
                    self.send(p.read_bytes(),mimetypes.guess_type(p.name)[0] or 'application/octet-stream',filename=p.name);return
                self.send({'error':'Not found'},code=404)
            except (ValueError,OSError,KeyError,TypeError,RecursionError): self.send({'error':'Requested artifact unavailable'},code=404)
        def do_POST(self):
            if not self.authorized(mutation=True): return
            try:
                if len(self.headers.get_all('Content-Length',[]))!=1 or len(self.headers.get_all('Content-Type',[]))!=1: raise PolicyError('one Content-Length and Content-Type header required')
                size=int(self.headers.get('Content-Length','0'))
                if self.headers.get('Transfer-Encoding') or not 0<size<=14_000_000 or self.headers.get_content_type()!='application/json': raise PolicyError('invalid request type or length')
                raw=self.rfile.read(size)
                if len(raw)!=size: raise PolicyError('incomplete request body')
                payload=json.loads(raw)
                if not isinstance(payload,dict): raise PolicyError('JSON object required')
                if self.path=='/api/jobs': self.send(jobs.submit(payload),code=202);return
                m=re.fullmatch(r'/api/jobs/([a-f0-9]{32})/cancel',self.path)
                if m: self.send(jobs.cancel(m[1]));return
                self.send({'error':'Not found'},code=404)
            except (ValueError,OSError,KeyError,TypeError,RecursionError) as e:
                self.send({'error':str(e) if isinstance(e,PolicyError) else 'Invalid request; verify input paths and configuration.'},code=400)
    try: server=BoundedHTTPServer(('127.0.0.1',port),Handler)
    except OSError:
        jobs.close();raise
    print(f'Dashboard: http://127.0.0.1:{port}\nUsername: operator\nSession password: {token}',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close();jobs.close()
