import argparse,json,os,signal,sys,tempfile,uuid
from pathlib import Path
from . import __version__
from .config import load
from .security import PolicyError,Scope,atomic,deny_network,extract_zip,write_json
from .models import dedup,now
from .preflight import doctor,EXTERNAL
from .reporting import reports,LIMITATIONS
from .store import Store

def scan(cfg,run_id=None):
    scope=Scope(json.loads(Path(cfg.scope).read_text()),allow_public=cfg.mode in ('internet','connected-ai')) if cfg.target else None
    result,provider=doctor(cfg,scope,check_target=bool(cfg.target))
    if not result['ready']: raise PolicyError('Preflight blocked assessment. See preflight_report.txt.')
    if not cfg.source and not cfg.target: raise PolicyError('provide --source or --target')
    # Persistent state and artifacts are opened before network isolation, never source code.
    store=Store(cfg.output)
    ident=run_id or uuid.uuid4().hex
    if len(ident)!=32 or any(c not in '0123456789abcdef' for c in ident): raise PolicyError('invalid run ID')
    directory=Path(cfg.output)/ident;directory.mkdir(mode=0o700)
    write_json(directory/'preflight_report.json',result)
    atomic(directory/'preflight_report.txt',(Path(cfg.output)/'preflight_report.txt').read_text())
    run={'id':ident,'status':'RUNNING','started':now(),'mode':cfg.mode,'network_policy':{'public_targets':cfg.mode in ('internet','connected-ai'),'online_advisories':'online_dependencies' in cfg.modules,'ai_enabled':cfg.ai.enabled},'findings':[],'assets':[],'components':[],'coverage':[],'events':[], 'limitations':LIMITATIONS,'ai_usage':{'enabled':cfg.ai.enabled,'provider':cfg.ai.provider,'verified':'not used'},'ai_suggestions':None}
    if cfg.mode=='internet':
        run['events'].append('Internet mode: scoped target access enabled; AI disabled.')
        if 'online_dependencies' in cfg.modules: run['events'].append('OSV lookups enabled: package ecosystem, name and version may leave this machine; source and credentials are excluded.')
    for row in result['components']:
        if row['status']!='READY': run['events'].append(row['component']+': '+row['status'])
    for name in cfg.modules:
        component='dependency database' if name=='dependencies' else name
        unavailable=next((r for r in result['components'] if r['component']==component and r['status']!='READY'),None)
        reason=unavailable['resolution'] or unavailable['status'] if unavailable else 'Not yet executed'
        run['coverage'].append({'module':name,'status':'NOT TESTED','reason':reason})
    store.save(run)
    if not cfg.target and not cfg.ai.enabled and 'online_dependencies' not in cfg.modules and not (set(cfg.modules)&EXTERNAL): deny_network()
    all_findings=[];all_assets=[]
    def checkpoint(findings,assets):
        run['findings']=[f.to_dict() for f in dedup(all_findings+findings)];run['assets']=all_assets+assets
        store.save(run);write_json(directory/'partial.json',run)
    def stop(signum, frame):
        raise KeyboardInterrupt()
    old_term=signal.signal(signal.SIGTERM,stop)
    old_alarm=signal.signal(signal.SIGALRM,stop)
    signal.setitimer(signal.ITIMER_REAL,cfg.timeout)
    try:
        if cfg.source:
            from .scanners import source_scan
            fs,assets,components,events=source_scan(cfg.source,cfg,checkpoint)
            all_findings+=fs;all_assets+=assets;run['components']=components;run['events']+=events
            for row in run['coverage']:
                if row['module'] in ('source','secrets','config','openapi'):
                    row.update(status='PARTIAL',reason='Bounded heuristic checks executed; manual validation required. Inventory records processed files.')
        if cfg.source and 'dependencies' in cfg.modules and cfg.advisory_dataset:
            from .datasets import Dataset
            try:
                ds=Dataset(cfg.advisory_dataset,cfg.dataset_max_age_days,cfg.block_stale_data)
                all_findings+=ds.scan(run['components'])
                for row in run['coverage']:
                    if row['module']=='dependencies': row.update(status='PARTIAL',reason='Exact version advisory matching; '+('STALE dataset; ' if ds.stale else '')+ds.manifest['version'])
                run['datasets']=[ds.manifest]
            except Exception:
                run['events'].append('Dependency assessment unavailable; dataset validation failed.')
        if cfg.source and 'online_dependencies' in cfg.modules:
            from .online import scan_dependencies
            fs,usage,events=scan_dependencies(run['components'],cfg)
            all_findings+=fs;run['online_advisories']=usage;run['events']+=events
            checkpoint([],[])
            for row in run['coverage']:
                if row['module']=='online_dependencies': row.update(status='PARTIAL' if usage['responses'] else 'NOT TESTED',reason=f"OSV: {usage['completed']} package queries completed, {usage['failed']} failed, {usage['skipped']} skipped. Inventory and advisory coverage are limited.")
            if cfg.strict and (usage['failed'] or usage['skipped']): raise PolicyError('Required online advisory coverage incomplete')
        for name in cfg.modules:
            if name in EXTERNAL and cfg.source:
                ready=any(r['component']==name and r['status']=='READY' for r in result['components'])
                if not ready: continue
                try:
                    from .adapters import execute
                    fs,sbom=execute(name,cfg.source,cfg.scanners.get(name,{}),cfg.timeout)
                    all_findings+=fs
                    if sbom: run['external_sbom']=sbom
                    for row in run['coverage']:
                        if row['module']==name: row.update(status='PARTIAL',reason='Isolated scanner completed; detections need review.')
                except Exception:
                    run['events'].append(name+': failed; no clean result claimed')
                    if cfg.strict: raise PolicyError('Required scanner failed')
        if cfg.target and 'web' in cfg.modules:
            from .network import scan_web
            fs,assets,events=scan_web(cfg.target,scope,checkpoint);all_findings+=fs;all_assets+=assets;run['events']+=events
            for row in run['coverage']:
                if row['module']=='web': row.update(status='PARTIAL' if assets else 'NOT TESTED',reason='Bounded GET crawl and header/cookie checks; no browser or authentication checks.' if assets else 'No HTTP responses available.')
        run['findings']=[f.to_dict() for f in dedup(all_findings)];run['assets']=all_assets
        if provider:
            try:
                run['ai_suggestions']=provider.suggest(run['findings']);run['ai_usage']['verified']='inference response validated'
            except Exception:
                run['events'].append('AI suggestion generation failed; deterministic evidence preserved.')
                if cfg.ai.failure_policy=='required': raise PolicyError('Required AI inference failed')
            finally: run['ai_usage'].update(requests=provider.requests,reserved_tokens=provider.tokens,estimated_upper_cost=provider.cost)
        from .frameworks import apply_mappings
        apply_mappings(run)
        run['status']='COMPLETED_WITH_LIMITATIONS'
    except KeyboardInterrupt:
        run['status']='CANCELLED';run['events'].append('Cancelled; partial evidence retained.')
    except Exception as e:
        run['status']='FAILED';run['events'].append(type(e).__name__+': assessment module failed; partial evidence retained.')
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGTERM,old_term);signal.signal(signal.SIGALRM,old_alarm)
        run['finished']=now();store.save(run);reports(directory,run)
        atomic(directory/'audit.jsonl',json.dumps({'timestamp':now(),'event':'assessment_finished','id':ident,'status':run['status']})+'\n')
        store.db.close()
    print(json.dumps({'run_id':ident,'status':run['status'],'findings':len(run['findings']),'reports':str(directory)}))
    return 1 if run['status'] in ('FAILED','CANCELLED') else 0

def main(argv=None):
    os.umask(0o077)
    p=argparse.ArgumentParser(prog='secaudit',description='Linux security assessment: internet or offline, no AI required. Linux/Python 3.11+.')
    p.add_argument('--version',action='version',version=__version__)
    sub=p.add_subparsers(dest='cmd',required=True)
    for name in ('doctor','scan'):
        q=sub.add_parser(name);q.add_argument('--config');q.add_argument('--source');q.add_argument('--target');q.add_argument('--scope');q.add_argument('--output');q.add_argument('--json',action='store_true')
        if name=='scan':
            q.add_argument('--archive');q.add_argument('--run-id')
    q=sub.add_parser('dashboard');q.add_argument('--output',default='runs');q.add_argument('--port',type=int,default=8765)
    q=sub.add_parser('resume',help='Recover interrupted state and regenerate saved reports; never repeat requests');q.add_argument('run_id');q.add_argument('--output',default='runs')
    q=sub.add_parser('scope',help='Create an authorization record and current DNS pins; no scan');q.add_argument('--origin',required=True);q.add_argument('--authorization',required=True);q.add_argument('--exclude',action='append',default=[]);q.add_argument('--output',required=True)
    q=sub.add_parser('dataset',help='Build an integrity manifest for an operator-supplied advisory snapshot');q.add_argument('--input',required=True);q.add_argument('--output',required=True);q.add_argument('--source',required=True);q.add_argument('--version',required=True);q.add_argument('--published-at',required=True)
    q=sub.add_parser('bundle');b=q.add_subparsers(dest='action',required=True)
    r=b.add_parser('prepare');r.add_argument('--output',required=True);r.add_argument('--download-dependencies',action='store_true',help='Explicit connected preparation: download locked PDF wheels')
    for name in ('verify','install'):
        r=b.add_parser(name);r.add_argument('bundle')
        if name=='install': r.add_argument('--destination',default='installed')
    a=p.parse_args(argv)
    try:
        if a.cmd=='scope':
            from .scopefile import create
            create(a.origin,a.authorization,a.exclude,a.output);print('Scope file created. Review paths and IP pins before scanning.');return 0
        if a.cmd=='dataset':
            from .datasets import build_snapshot
            build_snapshot(a.input,a.output,a.source,a.version,a.published_at);print('Validated advisory snapshot saved.');return 0
        if a.cmd=='bundle':
            from . import bundle
            result=bundle.prepare(a.output,a.download_dependencies) if a.action=='prepare' else bundle.verify(a.bundle) if a.action=='verify' else bundle.install(a.bundle,a.destination)
            print(json.dumps(result,indent=2));return 0
        if a.cmd=='dashboard':
            from .dashboard import serve
            serve(a.output,a.port);return 0
        if a.cmd=='resume':
            if not a.run_id.isalnum(): raise PolicyError('invalid run ID')
            s=Store(a.output);s.recover();run=s.get(a.run_id);reports(Path(a.output)/a.run_id,run);s.db.close();print('Reports regenerated from saved evidence; no checks repeated.');return 0
        cfg=load(a.config)
        for name in ('source','target','scope','output'):
            if getattr(a,name,None) is not None: setattr(cfg,name,getattr(a,name))
        if cfg.target and 'web' not in cfg.modules: cfg.modules.append('web')
        cfg.validate()
        if a.cmd=='doctor':
            scope=Scope(json.loads(Path(cfg.scope).read_text()),allow_public=cfg.mode in ('internet','connected-ai')) if cfg.target else None
            result,_=doctor(cfg,scope,check_target=bool(cfg.target))
            print(json.dumps(result,indent=2) if a.json else (Path(cfg.output)/'preflight_report.txt').read_text());return 0 if result['ready'] else 2
        if a.archive:
            if a.source: raise PolicyError('choose source or archive')
            with tempfile.TemporaryDirectory(prefix='secaudit-input-') as temp:
                cfg.source=str(extract_zip(a.archive,Path(temp)/'source',cfg.max_total_bytes,cfg.max_files));return scan(cfg,a.run_id)
        return scan(cfg,a.run_id)
    except (ValueError,OSError,KeyError,TypeError) as e:
        # Do not expose URLs, credentials, raw scanner/provider errors or source contents.
        print('Secaudit: '+(str(e) if isinstance(e,PolicyError) else type(e).__name__+'; check configuration and local paths.'),file=sys.stderr);return 2

if __name__=='__main__': raise SystemExit(main())
