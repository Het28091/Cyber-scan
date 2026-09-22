"""Persistent single-worker queue. Only the reviewed scanner entry point is executed."""
import base64,json,os,queue,signal,subprocess,sys,threading,time,uuid
from pathlib import Path
from .security import PolicyError,write_json,atomic
from .config import load
from .models import now
from dataclasses import asdict

class Jobs:
    def __init__(self,root):
        self.root=Path(root).resolve();self.folder=self.root/'.jobs';self.folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.tasks=queue.Queue();self.lock=threading.RLock();self.process=None;self.current=None;self.closed=False
        for path in self.folder.glob('*.json'):
            if path.name.endswith('.config.json'): continue
            try:
                job=json.loads(path.read_text())
                if job.get('status') in ('QUEUED','RUNNING'):
                    job.update(status='INTERRUPTED',finished=now());write_json(path,job)
            except (ValueError,OSError): continue
        self.worker=threading.Thread(target=self._worker,daemon=True);self.worker.start()
    def list(self):
        out=[]
        with self.lock:
            for p in self.folder.glob('*.json'):
                if p.name.endswith('.config.json'): continue
                try: out.append(json.loads(p.read_text()))
                except (OSError,ValueError): pass
        return sorted(out,key=lambda j:j['created'],reverse=True)[:200]
    def submit(self,data):
        if set(data)-{'source','target','scope','preset','archive_base64','archive_name'}: raise PolicyError('unknown job fields')
        preset=data.get('preset','offline')
        if preset not in ('offline','local-ai','api-ai'): raise PolicyError('invalid preset')
        project=Path(__file__).resolve().parent.parent
        cfg=load(project/'config'/(preset+'.json'))
        ident=uuid.uuid4().hex
        source=data.get('source','');target=data.get('target','')
        if not isinstance(source,str) or not isinstance(target,str): raise PolicyError('invalid source or target')
        cfg.source=source;cfg.target=target;cfg.output=str(self.root)
        archive=None
        if data.get('archive_base64'):
            if source: raise PolicyError('choose source or archive')
            raw=base64.b64decode(data['archive_base64'],validate=True)
            if len(raw)>10_000_000: raise PolicyError('ZIP upload exceeds 10 MB')
            if not raw.startswith(b'PK'): raise PolicyError('only ZIP uploads are accepted')
            upload=self.folder/(ident+'.zip')
            with upload.open('xb') as f: f.write(raw)
            upload.chmod(0o600);archive=str(upload)
        if not source and not target and not archive: raise PolicyError('source, ZIP or target is required')
        if target:
            from .security import Scope
            scope=data.get('scope')
            if not isinstance(scope,dict): raise PolicyError('scope JSON is required for a web target')
            Scope(scope) # Structural checks now; scoped DNS/connectivity preflight runs inside worker.
            scope_path=self.folder/(ident+'.scope');write_json(scope_path,scope);cfg.scope=str(scope_path)
            if 'web' not in cfg.modules: cfg.modules.append('web')
        cfg.validate()
        config=self.folder/(ident+'.config.json')
        # Operator config contains no API keys. Preserve source paths rather than redacting executable config.
        atomic(config,json.dumps(asdict(cfg)))
        job={'id':ident,'status':'QUEUED','created':now(),'mode':cfg.mode,'kind':'source + web' if (source or archive) and target else 'web' if target else 'source','run_id':ident}
        with self.lock:
            if self.closed: raise PolicyError('dashboard is shutting down')
            if len([j for j in self.list() if j['status'] in ('QUEUED','RUNNING')])>=10: raise PolicyError('queue limit reached')
            write_json(self.folder/(ident+'.json'),job);self.tasks.put((ident,config,archive))
        return job
    def cancel(self,ident):
        if not len(ident)==32 or any(c not in '0123456789abcdef' for c in ident): raise PolicyError('invalid job ID')
        with self.lock:
            path=self.folder/(ident+'.json');job=json.loads(path.read_text())
            if job['status'] not in ('QUEUED','RUNNING'): return job
            job['status']='CANCELLED';job['finished']=now();write_json(path,job)
            if self.current==ident and self.process and self.process.poll() is None:
                os.killpg(self.process.pid,signal.SIGTERM)
                try: self.process.wait(timeout=3)
                except subprocess.TimeoutExpired: os.killpg(self.process.pid,signal.SIGKILL)
            return job
    def _worker(self):
        while True:
            item=self.tasks.get()
            if item is None: return
            ident,config,archive=item;path=self.folder/(ident+'.json')
            try:
                with self.lock:
                    job=json.loads(path.read_text())
                    if job['status']!='QUEUED': continue
                    job['status']='RUNNING';write_json(path,job)
                    project=Path(__file__).resolve().parent.parent
                    command=[sys.executable,'-m','secaudit','scan','--config',str(config),'--run-id',ident]
                    if archive: command+=['--archive',archive]
                    env=dict(os.environ);env['PYTHONPATH']=str(project)
                    self.process=subprocess.Popen(command,cwd=project,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
                    self.current=ident;p=self.process
                try: p.wait(timeout=360)
                except subprocess.TimeoutExpired: self.cancel(ident)
                with self.lock:
                    job=json.loads(path.read_text())
                    if job['status']=='RUNNING': job['status']='COMPLETED' if p.returncode==0 else 'FAILED'
                    job['finished']=now();write_json(path,job);self.current=None;self.process=None
            except Exception:
                with self.lock:
                    job={'id':ident,'run_id':ident,'created':now(),'status':'FAILED','kind':'assessment','mode':'unknown'};write_json(path,job)
            finally:
                if archive: Path(archive).unlink(missing_ok=True)
                self.tasks.task_done()
    def close(self):
        with self.lock:
            self.closed=True
            if self.current: self.cancel(self.current)
            for j in self.list():
                if j['status']=='QUEUED': self.cancel(j['id'])
            self.tasks.put(None)
        self.worker.join(timeout=5)
