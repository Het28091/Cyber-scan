import ast,json,os,re,stat,time
from pathlib import Path
from .models import Finding
from .security import PolicyError

IGNORE={'.git','.venv','node_modules','__pycache__','runs'}
TEXT={'.py','.js','.ts','.jsx','.tsx','.json','.yaml','.yml','.env','.tf','.toml','.ini','.cfg','.txt','.xml','.conf','.sh','.properties','.in','.lock'}

def docker_runtime_user(text):
    """Track the final stage's declared user, including locally named stages.

    External image defaults and variable expansion remain unknown.
    """
    stages={};stage=None;user=None
    logical=re.sub(r'\\\r?\n', ' ', text)
    for line in logical.splitlines():
        parts=line.strip().split()
        if not parts or parts[0].startswith('#'):continue
        instruction=parts[0].upper()
        if instruction=='FROM':
            if stage is not None:stages[stage]=user
            args=[p for p in parts[1:] if not p.startswith('--')]
            user=stages.get(args[0].lower()) if args else None
            stage=args[2].lower() if len(args)>=3 and args[1].upper()=='AS' else None
        elif instruction=='USER':
            user=parts[1].split(':',1)[0] if len(parts)>1 else None
    return user

def files(root,cfg):
    root=Path(root).resolve()
    if not root.is_dir(): raise PolicyError('source must be a directory')
    count=total=0;started=time.monotonic()
    for parent,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in IGNORE and not (Path(parent)/d).is_symlink())
        for name in sorted(names):
            if time.monotonic()-started>cfg.timeout: raise PolicyError('source scan time budget exceeded')
            p=Path(parent)/name
            if p.is_symlink() or (p.suffix not in TEXT and name not in ('Dockerfile','.env')): continue
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode): continue
                count+=1;total+=st.st_size
                if count>cfg.max_files or total>cfg.max_total_bytes: raise PolicyError('source traversal budget exceeded')
                if st.st_size>cfg.max_file_bytes: raise PolicyError('file exceeds configured byte limit')
                with os.fdopen(fd,'rb',closefd=False) as f: raw=f.read(cfg.max_file_bytes+1)
                if len(raw)>cfg.max_file_bytes: raise PolicyError('file grew beyond limit')
            finally: os.close(fd)
            if b'\x00' in raw: continue
            yield p.relative_to(root).as_posix(),raw.decode('utf-8','replace')

def source_scan(root,cfg,checkpoint):
    findings=[];inventory=[];components=[];events=[]
    def add(rule,title,asset,line,description,remediation,severity='MEDIUM'):
        findings.append(Finding(rule,title,asset,description,remediation,severity=severity,line=line,evidence=[f'{asset}:{line}: pattern matched; source content omitted']))
    for name,text in files(root,cfg):
        inventory.append({'asset':name,'type':'source'})
        if 'source' in cfg.modules and name.endswith('.py'):
            try: tree=ast.parse(text)
            except SyntaxError: events.append('Python syntax could not be parsed: '+name);tree=None
            if tree:
                for node in ast.walk(tree):
                    if isinstance(node,ast.Call):
                        fname=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
                        if fname in ('eval','exec'):
                            add('PY-DYNAMIC-EXEC','Dynamic code execution requires review',name,node.lineno,'Dynamic execution can interpret untrusted input. This is a syntax-based candidate, not data-flow proof.','Remove dynamic evaluation or strictly validate trusted input.','HIGH')
                        if any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords):
                            add('PY-SHELL','Shell subprocess requires review',name,node.lineno,'shell=True enables shell interpretation.','Use an argument list with shell=False.','HIGH')
                        if fname=='loads' and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='pickle':
                            add('PY-PICKLE','Unsafe deserialization candidate',name,node.lineno,'Pickle can execute code when loading untrusted input.','Use a data-only format such as JSON.','HIGH')
                        if fname in ('execute','executemany') and node.args and (isinstance(node.args[0],ast.JoinedStr) or isinstance(node.args[0],ast.BinOp) and isinstance(node.args[0].op,(ast.Add,ast.Mod))):
                            add('PY-SQL-DYNAMIC','Constructed SQL argument requires review',name,node.lineno,'An execute call receives an interpolated or concatenated argument; database identity and untrusted input are not proven.','Use the database driver parameter-binding API and verify the input data flow.','HIGH')
                        if fname=='load' and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='yaml':
                            loader=next((k.value for k in node.keywords if k.arg=='Loader'),node.args[1] if len(node.args)>1 else None)
                            if loader is None or isinstance(loader,ast.Attribute) and loader.attr in ('Loader','UnsafeLoader'):
                                add('PY-YAML-LOAD','Potential unsafe YAML deserialization',name,node.lineno,'yaml.load uses an omitted or known unsafe loader; actual library version and input trust need review.','Use yaml.safe_load or an explicitly reviewed SafeLoader.','HIGH')
        for ln,line in enumerate(text.splitlines(),1):
            if 'secrets' in cfg.modules and re.search(r'''(?i)(?:password|api[_-]?key|secret|token)\s*[:=]\s*["'][^"']{8,}["']''',line):
                add('SECRET-LITERAL','Potential hardcoded credential',name,ln,'A credential-like assignment contains a literal. Value intentionally discarded.','Review whether the value is sensitive; rotate exposed credentials and use a secret store.','HIGH')
            if 'config' in cfg.modules:
                if re.search(r'(?i)\bdebug\s*[:=]\s*(?:true|1)\b',line): add('CONFIG-DEBUG','Debug mode enabled',name,ln,'Debug setting is enabled.','Disable debug mode in production.')
                if re.search(r'(?i)\bverify\s*=\s*False\b',line): add('CONFIG-TLS','TLS verification disabled',name,ln,'Certificate verification is disabled.','Use certificate validation and a trusted CA bundle.','HIGH')
        runtime_user=docker_runtime_user(text) if Path(name).name=='Dockerfile' else None
        if 'config' in cfg.modules and Path(name).name=='Dockerfile' and (not runtime_user or runtime_user=='root' or runtime_user.isdecimal() and int(runtime_user)==0 or '$' in runtime_user):
            add('DOCKER-USER','No explicit non-root Docker user',name,1,'The Dockerfile does not explicitly select a non-root user; base image defaults are unknown.','Choose a non-root runtime user.')
        from .inventory import parse_manifest
        parsed=parse_manifest(name,text)
        if parsed is not None:
            cs,summary=parsed;components.extend(cs);inventory.append(summary)
            events.append(f"Inventory {name}: {summary['pinned']}/{summary['total']} exact pins; {summary['unresolved']} unresolved, {summary['invalid']} invalid, {summary['unsupported']} unsupported; {summary['conditional']} conditional declarations retained. This is declaration coverage, not installed-package completeness.")
        if {'openapi','config'} & set(cfg.modules) and name.endswith('.json'):
            try: document=json.loads(text)
            except (ValueError,RecursionError):
                events.append('JSON declaration could not be parsed: '+name)
            else:
                from .declarations import inspect_document
                declared,assets,limitations=inspect_document(name,document,cfg.modules)
                findings.extend(declared);inventory.extend(assets);events.extend(limitations)
        checkpoint(findings,inventory)
    return findings,inventory,components,events
