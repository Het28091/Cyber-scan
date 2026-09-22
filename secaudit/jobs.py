"""Persistent single-worker queue. Only the reviewed scanner entry point is executed."""
import base64,fcntl,json,os,queue,re,signal,subprocess,sys,threading,time,uuid
from pathlib import Path
from .security import PolicyError,write_json,atomic
from .config import load
from .models import now
from dataclasses import asdict

class Jobs:
    def __init__(self,root):
        self.root=Path(root).resolve();self.folder=self.root/'.jobs';self.folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        lockfd=os.open(self.folder/'dashboard.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        self.owner_lock=os.fdopen(lockfd,'w')
        try: fcntl.flock(self.owner_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.owner_lock.close();raise PolicyError('another dashboard already owns this output directory')
        self.tasks=queue.Queue();self.lock=threading.RLock();self.process=None;self.current=None;self.closed=False
        for path in self.folder.glob('*.json'):
            if path.name.endswith('.config.json'): continue
            try:
                job=json.loads(path.read_text())
                if job.get('status') in ('QUEUED','RUNNING'):
                    job.update(status='INTERRUPTED',finished=now());write_json(path,job)
            except (ValueError,OSError,AttributeError,TypeError): continue
        for upload in self.folder.glob('*.zip'): upload.unlink(missing_ok=True)
        self.prune()
        self.worker=threading.Thread(target=self._worker,daemon=True);self.worker.start()
    def list(self,limit=200):
        out=[]
        with self.lock:
            for p in self.folder.glob('*.json'):
                if p.name.endswith('.config.json'): continue
                try:
                    value=json.loads(p.read_text())
                    if isinstance(value,dict) and all(isinstance(value.get(k),str) for k in ('id','created','status')): out.append(value)
                except (OSError,ValueError): pass
        return sorted(out,key=lambda j:j['created'],reverse=True)[:limit]
    def prune(self):
        """Retain 200 terminal job summaries. Assessment evidence is never pruned."""
        with self.lock:
            terminal=[]
            for job in self.list(None):
                ident=job['id']
                if not re.fullmatch('[a-f0-9]{32}',ident): continue
                if job['status'] in ('QUEUED','RUNNING'): continue
                for suffix in ('.config.json','.scope','.zip'):
                    (self.folder/(ident+suffix)).unlink(missing_ok=True)
                terminal.append(job)
            for job in terminal[200:]:
                (self.folder/(job['id']+'.json')).unlink(missing_ok=True)
            # Remove orphan execution inputs left by a process killed before job persistence.
            for pattern,suffix in (('*.config.json','.config.json'),('*.scope','.scope')):
                for path in self.folder.glob(pattern):
                    ident=path.name[:-len(suffix)]
                    if re.fullmatch('[a-f0-9]{32}',ident) and not (self.folder/(ident+'.json')).exists(): path.unlink(missing_ok=True)
    def diagnostic(self,ident,returncode):
        result={'exit_code':returncode,'code':'PROCESS_FAILED','message':'Assessment process failed; review saved partial evidence.'}
        if returncode==0: return {'exit_code':0,'code':'COMPLETED','message':'Assessment completed; review coverage and limitations.'}
        if returncode==2:
            result.update(code='PREFLIGHT_OR_INPUT_REJECTED',message='Preflight or input validation blocked the scan. Check source/archive, scope, dependencies and configuration.')
            try:
                preflight=json.loads((self.root/'preflight_report.json').read_text())
                blocked=[r['component']+': '+r['status'] for r in preflight.get('components',[]) if r.get('status') not in ('READY','OPTIONAL_UNAVAILABLE')]
                if blocked: result['message']+=' Preflight: '+('; '.join(blocked))[:1000]
            except (OSError,ValueError,TypeError,KeyError,AttributeError): pass
        try:
            run=json.loads((self.root/ident/'run.json').read_text())
            if isinstance(run,dict) and run.get('status') in ('FAILED','CANCELLED'):
                result.update(code=run['status'],message='Assessment '+run['status'].lower()+'. Saved run events and partial evidence explain coverage.')
        except (OSError,ValueError): pass
        return result
    def submit(self,data):
        if set(data)-{'source','target','scope','preset','archive_base64','archive_name'}: raise PolicyError('unknown job fields')
        preset=data.get('preset','internet')
        if preset not in ('offline','internet'): raise PolicyError('invalid preset')
        project=Path(__file__).resolve().parent.parent
        cfg=load(project/'config'/(preset+'.json'))
        ident=uuid.uuid4().hex
        source=data.get('source','');target=data.get('target','')
        if not isinstance(source,str) or not isinstance(target,str): raise PolicyError('invalid source or target')
        cfg.source=source;cfg.target=target;cfg.output=str(self.root)
        archive=None;raw=None;scope=None
        if data.get('archive_base64'):
            if source: raise PolicyError('choose source or archive')
            encoded=data['archive_base64']
            if not isinstance(encoded,str) or len(encoded)>13_333_336: raise PolicyError('invalid or oversized ZIP encoding')
            raw=base64.b64decode(encoded,validate=True)
            if len(raw)>10_000_000: raise PolicyError('ZIP upload exceeds 10 MB')
            if not raw.startswith(b'PK'): raise PolicyError('only ZIP uploads are accepted')
            archive=str(self.folder/(ident+'.zip'))
        if not source and not target and not archive: raise PolicyError('source, ZIP or target is required')
        if target:
            from .security import Scope
            scope=data.get('scope')
            if not isinstance(scope,dict): raise PolicyError('scope JSON is required for a web target')
            Scope(scope)
            cfg.scope=str(self.folder/(ident+'.scope'))
            if 'web' not in cfg.modules: cfg.modules.append('web')
        cfg.validate()
        config=self.folder/(ident+'.config.json')
        job={'id':ident,'status':'QUEUED','created':now(),'mode':cfg.mode,'kind':'source + web' if (source or archive) and target else 'web' if target else 'source','run_id':ident}
        # Reserve capacity and validate before writing; roll back every rejected submission.
        with self.lock:
            if self.closed: raise PolicyError('dashboard is shutting down')
            if len([j for j in self.list(None) if j['status'] in ('QUEUED','RUNNING')])>=10: raise PolicyError('queue limit reached')
            created=[]
            try:
                if archive:
                    with Path(archive).open('xb') as f:
                        created.append(Path(archive));os.fchmod(f.fileno(),0o600);f.write(raw)
                if scope is not None:
                    created.append(Path(cfg.scope));atomic(cfg.scope,json.dumps(scope))
                created.append(config);atomic(config,json.dumps(asdict(cfg)))
                path=self.folder/(ident+'.json');created.append(path);write_json(path,job)
                self.tasks.put((ident,config,archive))
            except Exception:
                for path in created: path.unlink(missing_ok=True)
                raise
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
                    for filename in ('preflight_report.json','preflight_report.txt'):
                        (self.root/filename).unlink(missing_ok=True)
                    self.process=subprocess.Popen(command,cwd=project,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
                    self.current=ident;p=self.process
                try: p.wait(timeout=360)
                except subprocess.TimeoutExpired: self.cancel(ident)
                with self.lock:
                    job=json.loads(path.read_text())
                    if job['status']=='RUNNING': job['status']='COMPLETED' if p.returncode==0 else 'FAILED'
                    job['finished']=now();job['diagnostic']=self.diagnostic(ident,p.returncode);write_json(path,job);self.current=None;self.process=None
            except Exception:
                with self.lock:
                    job={'id':ident,'run_id':ident,'created':now(),'status':'FAILED','kind':'assessment','mode':'unknown','diagnostic':{'code':'WORKER_ERROR','message':'Worker could not start or record this assessment. Check local permissions and disk space.'}};write_json(path,job);self.current=None;self.process=None
            finally:
                if archive: Path(archive).unlink(missing_ok=True)
                config.unlink(missing_ok=True)
                (self.folder/(ident+'.scope')).unlink(missing_ok=True)
                self.prune()
                self.tasks.task_done()
    def close(self):
        with self.lock:
            self.closed=True
            if self.current: self.cancel(self.current)
            for j in self.list():
                if j['status']=='QUEUED': self.cancel(j['id'])
            self.tasks.put(None)
        self.worker.join(timeout=5)
        if not self.worker.is_alive(): self.owner_lock.close()
