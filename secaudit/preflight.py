import json,os,platform,shutil,subprocess,sys,tempfile
from pathlib import Path
from .security import Scope,atomic,write_json,PolicyError
from .ai import Provider
from . import __version__

EXTERNAL={'gitleaks','semgrep','trivy','syft'}
def doctor(cfg,scope=None,check_target=False):
    rows=[];provider=None
    def row(component,status,version='',resolution='',required=True): rows.append({'component':component,'required_for':'assessment' if required else 'optional module','version':version,'status':status,'resolution':resolution,'required':required})
    cfg.validate()
    row('runtime','READY' if sys.version_info>=(3,11) and platform.system()=='Linux' else 'INCOMPATIBLE',platform.python_version(), 'Use Linux with Python 3.11+.' )
    try:
        out=Path(cfg.output);out.mkdir(parents=True,exist_ok=True,mode=0o700)
        with tempfile.TemporaryFile(dir=out): pass
        if shutil.disk_usage(out).free<100_000_000: raise OSError('insufficient disk space')
        row('evidence storage','READY')
    except OSError: row('evidence storage','REQUIRED_MISSING',resolution='Provide a writable output directory with at least 100 MB free.')
    try:
        available=os.sysconf('SC_AVPHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')
        row('resources','READY' if available>=128*1024*1024 else 'REQUIRED_MISSING',f'{os.cpu_count()} CPUs', 'At least 128 MiB available memory required.')
    except (ValueError,OSError): row('resources','INCOMPATIBLE',resolution='Cannot determine available memory.')
    if not cfg.target and not cfg.ai.enabled:
        probe='import sys; sys.path.insert(0, '+repr(str(Path(__file__).resolve().parent.parent))+'); from secaudit.security import deny_network; import socket; deny_network();\ntry: socket.socket()\nexcept PermissionError: raise SystemExit(0)\nraise SystemExit(1)'
        try:
            p=subprocess.run([sys.executable,'-c',probe],capture_output=True,timeout=5)
            row('kernel source isolation','READY' if p.returncode==0 else 'POLICY_BLOCKED',resolution='Install libseccomp2 and use a kernel permitting seccomp filters.')
        except (OSError,subprocess.TimeoutExpired): row('kernel source isolation','POLICY_BLOCKED')
    if cfg.target:
        try:
            if scope is None: raise PolicyError('scope missing')
            scope.check(cfg.target)
            row('target scope','READY')
            if check_target:
                from .network import request
                status,_,_=request(cfg.target,scope,method='HEAD',max_bytes=0)
                row('target connectivity','UNREACHABLE' if status>=500 else 'READY',str(status), 'Check target health; HEAD 4xx does not mean the target is unreachable.')
        except (ValueError,OSError): row('target scope/connectivity','POLICY_BLOCKED',resolution='Supply authorization, exact origin/path and current IP pins; verify target availability.')
    if cfg.source and not Path(cfg.source).is_dir(): row('source','REQUIRED_MISSING',resolution='Supply a readable local directory.')
    for name in cfg.modules:
        if name in EXTERNAL:
            try:
                from .adapters import probe
                _,version=probe(name,cfg.scanners.get(name,{}))
                row(name,'READY',version,required=cfg.strict)
            except Exception as e:
                message=str(e) if isinstance(e,PolicyError) else 'Adapter preflight failed'
                status=next((x for x in ('POLICY_BLOCKED','DATA_MISSING','INCOMPATIBLE','REQUIRED_MISSING') if message.startswith(x)),'INCOMPATIBLE')
                row(name,status,resolution=message,required=cfg.strict)
        elif name=='dependencies':
            try:
                from .datasets import Dataset
                ds=Dataset(cfg.advisory_dataset,cfg.dataset_max_age_days,cfg.block_stale_data)
                row('dependency database','DATA_STALE' if ds.stale else 'READY',ds.manifest['version'], 'Exact enumerated versions only; not complete ecosystem coverage.',required=cfg.strict and (not ds.stale or cfg.block_stale_data))
            except Exception as e:
                row('dependency database','DATA_MISSING',resolution=str(e) if isinstance(e,PolicyError) else 'Invalid dataset/manifest',required=cfg.strict)
        elif name=='web' and not cfg.target: row(name,'OPTIONAL_UNAVAILABLE',resolution='Provide --target and --scope.',required=cfg.strict)
        elif name!='web' and not cfg.source: row(name,'OPTIONAL_UNAVAILABLE',resolution='Provide --source.',required=cfg.strict)
        else: row(name,'READY',__version__)
    try:
        import reportlab
        row('PDF renderer','READY',reportlab.Version,required=cfg.pdf_required)
    except ImportError:
        row('PDF renderer','OPTIONAL_UNAVAILABLE',resolution='Run setup to install locked report dependencies.',required=cfg.pdf_required)
    if cfg.ai.enabled:
        try: provider=Provider(cfg);provider.health();row('AI','READY',cfg.ai.model,required=cfg.ai.failure_policy=='required')
        except Exception:
            provider=None;row('AI','OPTIONAL_UNAVAILABLE',resolution='Check endpoint, credentials, advertised model and budgets. No provider response logged.',required=cfg.ai.failure_policy=='required')
    result={'ready':all(x['status']=='READY' for x in rows if x['required']), 'mode':cfg.mode,'components':rows,'limitations':['Optional modules are NOT TESTED when unavailable. External scanners require working Bubblewrap isolation.']}
    write_json(Path(cfg.output)/'preflight_report.json',result)
    atomic(Path(cfg.output)/'preflight_report.txt','Component | Required for | Detected version | Status | Resolution\n'+'\n'.join(' | '.join(str(r[k]) for k in ('component','required_for','version','status','resolution')) for r in rows)+'\n')
    return result,provider
