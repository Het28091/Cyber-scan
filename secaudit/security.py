from __future__ import annotations
import ctypes, ctypes.util, errno, hashlib, ipaddress, json, os, re, socket, stat, tempfile, zipfile
from pathlib import Path
from urllib.parse import urlsplit, unquote

class PolicyError(ValueError):
    pass

SECRET = re.compile(r'''(?i)(["']?(?:password|passwd|secret|api[_-]?key|token|authorization|cookie|set-cookie)["']?\s*[:=]\s*)(?:["'][^"'\r\n]*["']|[^\s,;}]+)''')
def redact(value):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if re.search(r'(?i)^(password|secret|token|api.?key|authorization|cookie|set-cookie)$', str(k)) else redact(v) for k,v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    if not isinstance(value,str): return value
    value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]', value, flags=re.S)
    value = re.sub(r'\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b', '[REDACTED TOKEN]', value)
    value = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[REDACTED EMAIL]', value)
    return SECRET.sub(lambda m:m[1]+'[REDACTED]',value)

def atomic(path: Path, data: str):
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def write_json(path, obj): atomic(Path(path),json.dumps(redact(obj),indent=2,ensure_ascii=True)+'\n')
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def csv_safe(value):
    s=str(value)
    return "'"+s if s.lstrip().startswith(('=','+','-','@','\t','\r','\n')) else s

def deny_network():
    """Irreversible kernel filter, inherited by child processes. Linux/libseccomp."""
    libname=ctypes.util.find_library('seccomp')
    if not libname: raise PolicyError('libseccomp is required for source-only isolation')
    lib=ctypes.CDLL(libname,use_errno=True)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint]
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_release.argtypes=[ctypes.c_void_p]
    ctx=lib.seccomp_init(0x7fff0000)
    if not ctx: raise PolicyError('seccomp initialization failed')
    try:
        for name in ('socket','socketpair','connect','sendto','sendmsg','sendmmsg','socketcall','io_uring_setup'):
            nr=lib.seccomp_syscall_resolve_name(name.encode())
            if nr>=0 and lib.seccomp_rule_add(ctx,0x00050000|errno.EPERM,nr,0): raise PolicyError('seccomp rule failed')
        if lib.seccomp_load(ctx): raise PolicyError('kernel rejected seccomp policy')
    finally: lib.seccomp_release(ctx)

def canonical(url):
    if not isinstance(url,str) or any(ord(c)<33 for c in url) or '\\' in url: raise PolicyError('invalid URL')
    u=urlsplit(url)
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.fragment: raise PolicyError('invalid URL authority')
    try: port=u.port or (443 if u.scheme=='https' else 80)
    except ValueError: raise PolicyError('invalid port')
    host=u.hostname.encode('idna').decode().lower().rstrip('.')
    if '%' in host: raise PolicyError('scoped IPv6 not supported')
    path=u.path or '/'
    decoded=unquote(path)
    if '%' in decoded or '\\' in decoded or any(x in ('.','..') for x in decoded.split('/')) or '//' in decoded or any(ord(c)<32 for c in decoded): raise PolicyError('ambiguous path encoding')
    if unquote(path).count('/')!=path.count('/'): raise PolicyError('encoded path separators')
    host_text='['+host+']' if ':' in host else host
    return f'{u.scheme}://{host_text}:{port}', decoded, host, port

class Scope:
    def __init__(self, data, allow_public=True):
        self.allow_public=allow_public
        required={'authorization','origins','exclusions','environment','profiles','max_requests','max_seconds','allowed_ips'}
        if not required<=data.keys(): raise PolicyError('scope is incomplete')
        if not isinstance(data['authorization'],str) or len(data['authorization'].strip())<5: raise PolicyError('authorization reference required')
        if data['profiles']!=['passive']: raise PolicyError('only passive profile supported')
        if type(data['max_requests']) is not int or not 1<=data['max_requests']<=100: raise PolicyError('request limit must be 1..100')
        if type(data['max_seconds']) is not int or not 1<=data['max_seconds']<=300: raise PolicyError('time limit must be 1..300')
        if not data['origins'] or not data['allowed_ips']: raise PolicyError('explicit origins and IP pins required')
        self.data=data
        self.allow=[self._entry(x) for x in data['origins']]
        self.deny=[self._entry(x) for x in data['exclusions']]
        self.ips={str(ipaddress.ip_address(x)) for x in data['allowed_ips']}
    def _entry(self,x):
        origin,path,_,_=canonical(x)
        if urlsplit(x).query: raise PolicyError('scope entries cannot contain queries')
        return origin,path
    def check(self,url):
        origin,path,host,port=canonical(url)
        def matches(entries): return any(origin==o and (p=='/' or path==p or path.startswith(p.rstrip('/')+'/')) for o,p in entries)
        if matches(self.deny) or not matches(self.allow): raise PolicyError('URL outside authorized scope')
        addresses={str(ipaddress.ip_address(r[4][0])) for r in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)}
        if not self.allow_public and any(ipaddress.ip_address(x).is_global for x in addresses): raise PolicyError('public targets require internet mode')
        if not addresses or not addresses<=self.ips: raise PolicyError('DNS result differs from authorized IP pins')
        return sorted(addresses)[0]

def extract_zip(archive, destination, max_bytes=50_000_000,max_files=5000):
    dest=Path(destination)
    if dest.exists(): raise PolicyError('archive destination must not exist')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist()
        if len(entries)>max_files or sum(x.file_size for x in entries)>max_bytes: raise PolicyError('archive limit exceeded')
        seen=set()
        for x in entries:
            p=Path(x.filename); mode=x.external_attr>>16
            if p.is_absolute() or '..' in p.parts or '\\' in x.filename or ':' in x.filename or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR)): raise PolicyError('unsafe archive entry')
            if str(p) in seen: raise PolicyError('duplicate archive entry')
            seen.add(str(p))
        dest.mkdir(mode=0o700,parents=True)
        total=0
        for x in entries:
            p=dest/x.filename
            if x.is_dir(): p.mkdir(parents=True,exist_ok=True,mode=0o700);continue
            p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with z.open(x) as src, p.open('xb') as out:
                os.chmod(p,0o600)
                while chunk:=src.read(65536):
                    total+=len(chunk)
                    if total>max_bytes: raise PolicyError('expanded archive exceeds limit')
                    out.write(chunk)
    return dest
