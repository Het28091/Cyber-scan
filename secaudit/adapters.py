"""Optional source scanner adapters. Bubblewrap isolation is mandatory."""
import json,os,re,resource,signal,subprocess,tempfile,time
from pathlib import Path
from .security import PolicyError
from .models import Finding

# Gitleaks' WASM regex runtime reserves 4 GiB even for `version`.
# This is virtual address space, not a resident-memory/cgroup guarantee.
ADDRESS_LIMITS={'gitleaks':8*1024**3}

VERSIONS={'gitleaks':r'\b8\.\d+\.\d+\b','semgrep':r'\b1\.\d+\.\d+\b','trivy':r'\b0\.\d+\.\d+\b','syft':r'\b1\.\d+\.\d+\b'}

def sandbox_command(executable,source=None,extra=None):
    import shutil
    bwrap=shutil.which('bwrap')
    if not bwrap: raise PolicyError('Bubblewrap is missing')
    cmd=[bwrap,'--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/local/bin:/usr/bin:/bin','--setenv','HOME','/tmp','--setenv','LC_ALL','C.UTF-8','--tmpfs','/tmp','--proc','/proc','--dev','/dev']
    for d in ('/usr','/bin','/lib','/lib64'):
        if Path(d).exists(): cmd+=['--ro-bind',d,d]
    exe=Path(executable).resolve()
    if not any(exe.is_relative_to(p) for p in (Path('/usr'),Path('/bin'),Path('/lib'),Path('/lib64'))):
        cmd+=['--ro-bind',str(exe.parent),'/tool'];executable='/tool/'+exe.name
    if source: cmd+=['--ro-bind',str(Path(source).resolve()),'/input','--chdir','/tmp']
    for host,guest in (extra or []): cmd+=['--ro-bind',str(Path(host).resolve()),guest]
    return cmd+['--',str(executable)]

def bounded(command,timeout=60,max_bytes=10_000_000,max_address_bytes=2*1024**3):
    """Drain both streams without unbounded buffers; terminate the whole process group."""
    import selectors
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(max_bytes,max_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
        resource.setrlimit(resource.RLIMIT_AS,(max_address_bytes,max_address_bytes))
        resource.setrlimit(resource.RLIMIT_CPU,(max(1,int(timeout)),max(2,int(timeout)+1)))
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits)
    selector=selectors.DefaultSelector();selector.register(p.stdout,selectors.EVENT_READ);selector.register(p.stderr,selectors.EVENT_READ)
    output={p.stdout:bytearray(),p.stderr:bytearray()};start=time.monotonic();size=0
    try:
        while selector.get_map():
            if time.monotonic()-start>timeout: raise PolicyError('scanner timed out')
            for key,_ in selector.select(.1):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk: selector.unregister(key.fileobj);continue
                size+=len(chunk)
                if size>max_bytes: raise PolicyError('scanner output limit exceeded')
                output[key.fileobj].extend(chunk)
        code=p.wait(timeout=2)
        return code,bytes(output[p.stdout]) # stderr deliberately never persisted
    finally:
        selector.close()
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGKILL);p.wait()
        p.stdout.close();p.stderr.close()

def probe(name,options):
    import shutil
    exe=options.get('executable') or shutil.which(name)
    if not exe: raise PolicyError('REQUIRED_MISSING: '+name)
    code,_=bounded(sandbox_command('/bin/true'),5,65536)
    if code: raise PolicyError('POLICY_BLOCKED: kernel does not permit Bubblewrap isolation')
    code,raw=bounded(sandbox_command(exe)+(['version'] if name in ('gitleaks','syft') else ['--version']),10,65536,max_address_bytes=ADDRESS_LIMITS.get(name,2*1024**3))
    if code: raise PolicyError('INCOMPATIBLE: tool cannot start inside sandbox')
    match=re.search(VERSIONS[name],raw.decode('utf-8','replace'))
    if not match: raise PolicyError('INCOMPATIBLE: unsupported scanner version output')
    if name=='semgrep' and not Path(options.get('rules','')).is_file(): raise PolicyError('DATA_MISSING: local Semgrep rule file required')
    if name=='trivy' and not (Path(options.get('cache',''))/'db/trivy.db').is_file(): raise PolicyError('DATA_MISSING: Trivy local database required')
    return str(exe),match[0]

def parse(name,raw,version):
    if name not in VERSIONS: raise PolicyError('unknown scanner')
    try:
        result=_parse(name,raw,version)
        if any(f.line<0 for f in result[0]): raise PolicyError('invalid finding line')
        return result
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
        raise PolicyError('invalid scanner output; raw content discarded') from None

def _parse(name,raw,version):
    data=json.loads(raw);fs=[]
    if name=='gitleaks':
        if not isinstance(data,list): raise PolicyError('invalid Gitleaks JSON')
        for r in data:
            fs.append(Finding('GITLEAKS-'+r['RuleID'],'Potential secret detected',str(r['File']).removeprefix('/input/'), 'A secret detector matched this location; raw match and secret discarded.','Validate, rotate any exposed credential, and remove it from source/history.',severity='HIGH',line=int(r['StartLine']),scanner=name,scanner_version=version,evidence=['Rule: '+r['RuleID']]))
    elif name=='semgrep':
        if not isinstance(data.get('results'),list) or data.get('errors'): raise PolicyError('Semgrep errors or invalid output')
        for r in data['results']:
            fs.append(Finding('SEMGREP-'+r['check_id'],'Static analysis candidate',r['path'].removeprefix('/input/'),'Local Semgrep rule matched. Source snippet omitted.','Review the rule and remove the unsafe data flow.',line=int(r['start']['line']),scanner=name,scanner_version=version,evidence=['Rule: '+r['check_id']]))
    elif name=='trivy':
        if not isinstance(data.get('Results'),list): raise PolicyError('invalid Trivy JSON')
        for result in data['Results']:
            for v in result.get('Vulnerabilities') or []:
                fs.append(Finding('TRIVY-'+v['VulnerabilityID'],'Dependency vulnerability: '+v['VulnerabilityID'],result['Target'],str(v.get('Title','Local vulnerability database match')), 'Upgrade '+v['PkgName']+' to '+str(v.get('FixedVersion') or 'a vendor-confirmed unaffected version'),severity=v.get('Severity','MEDIUM') if v.get('Severity') in ('CRITICAL','HIGH','MEDIUM','LOW') else 'MEDIUM',confidence='HIGH',scanner=name,scanner_version=version,evidence=['Package: '+v['PkgName'],'Installed version: '+v['InstalledVersion']]))
    elif name=='syft':
        if data.get('bomFormat')!='CycloneDX': raise PolicyError('invalid Syft CycloneDX output')
        return [],data
    return fs,None

def execute(name,source,options,timeout):
    exe,version=probe(name,options);extra=[]
    if name=='gitleaks': args=['dir','/input','--no-banner','--redact=100','--report-format','json','--report-path','-','--exit-code','0']
    elif name=='semgrep':
        extra=[(options['rules'],'/rules.yaml')];args=['scan','--config','/rules.yaml','--metrics=off','--disable-version-check','--json','--no-git-ignore','/input']
    elif name=='trivy':
        extra=[(options['cache'],'/cache')];args=['fs','--cache-dir','/cache','--scan-cache','memory','--skip-version-check','--offline-scan','--skip-db-update','--skip-java-db-update','--scanners','vuln','--format','json','/input']
    else: args=['dir:/input','-o','cyclonedx-json','--check-for-app-update=false']
    code,raw=bounded(sandbox_command(exe,source,extra)+args,timeout,max_address_bytes=ADDRESS_LIMITS.get(name,2*1024**3))
    if code: raise PolicyError('scanner failed; raw output discarded')
    return parse(name,raw,version)
