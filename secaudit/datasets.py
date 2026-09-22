"""Integrity-checked offline advisory snapshots. No runtime downloads."""
import hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
from .security import PolicyError
from .models import Finding

class Dataset:
    def __init__(self,path,max_age_days=30,block_stale=False):
        p=Path(path)
        if not p.is_file(): raise PolicyError('DATA_MISSING: advisory snapshot absent')
        if p.stat().st_size>100_000_000: raise PolicyError('dataset exceeds 100 MB limit')
        self.manifest=json.loads(p.with_suffix('.manifest.json').read_text(encoding='utf-8'))
        if not isinstance(self.manifest,dict) or any(not isinstance(self.manifest.get(k),str) or not self.manifest[k] for k in ('source','version','published_at','sha256')): raise PolicyError('invalid dataset manifest fields')
        raw=p.read_bytes()
        if self.manifest.get('sha256')!=hashlib.sha256(raw).hexdigest(): raise PolicyError('INCOMPATIBLE: dataset integrity mismatch')
        if self.manifest.get('schema')!=1 or not self.manifest.get('source') or not self.manifest.get('version'): raise PolicyError('INCOMPATIBLE: dataset manifest')
        published=datetime.fromisoformat(self.manifest['published_at'].replace('Z','+00:00'))
        if published.tzinfo is None: raise PolicyError('dataset timestamp must include timezone')
        self.age=(datetime.now(timezone.utc)-published).total_seconds()/86400
        if self.age < -1: raise PolicyError('dataset timestamp is in the future')
        self.stale=self.age>max_age_days
        if self.stale and block_stale: raise PolicyError('DATA_STALE: update the local advisory snapshot during preparation')
        data=json.loads(raw)
        if not isinstance(data,list): raise PolicyError('dataset must be an advisory array')
        self.records=[]
        for r in data:
            if not isinstance(r,dict) or not {'id','ecosystem','name','affected_versions','summary','source'}<=r.keys(): raise PolicyError('invalid advisory record')
            if not all(isinstance(r[k],str) and r[k] for k in ('id','ecosystem','name','summary','source')): raise PolicyError('invalid advisory text')
            if not isinstance(r['affected_versions'],list) or not all(isinstance(v,str) for v in r['affected_versions']): raise PolicyError('invalid advisory versions')
            if r.get('severity','MEDIUM') not in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'): raise PolicyError('invalid advisory severity')
            if 'remediation' in r and not isinstance(r['remediation'],str): raise PolicyError('invalid advisory remediation')
            self.records.append(r)
    def scan(self,components):
        fs=[]
        for c in components:
            eco='PyPI' if c.get('purl','').startswith('pkg:pypi/') else 'npm' if c.get('purl','').startswith('pkg:npm/') else ''
            canonical=lambda s:re.sub(r'[-_.]+','-',s).lower() if eco=='PyPI' else s
            for r in self.records:
                if eco==r['ecosystem'] and canonical(c['name'])==canonical(r['name']) and c['version'] in r['affected_versions']:
                    fs.append(Finding('DEP-'+r['id'],'Dependency advisory: '+r['id'],c['purl'],r['summary'],r.get('remediation','Upgrade to a version confirmed unaffected by the cited advisory.'),severity=r.get('severity','MEDIUM'),confidence='HIGH',scanner='local-advisory-matcher',scanner_version='1.0',evidence=['Exact installed/declaration version matched advisory '+r['id'],'Source: '+r['source']],provenance=[{'dataset':self.manifest['version'],'sha256':self.manifest['sha256']}]))
        return fs

def build_snapshot(input_file,output_file,source,version,published_at):
    # Operator supplies normalized advisory data; never infer unsupported version ranges.
    p=Path(output_file)
    if p.exists() or p.is_symlink() or p.with_suffix('.manifest.json').exists() or p.with_suffix('.manifest.json').is_symlink(): raise PolicyError('snapshot output already exists; use a new versioned filename')
    raw=Path(input_file).read_bytes()
    if len(raw)>100_000_000: raise PolicyError('snapshot too large')
    data=json.loads(raw)
    if not isinstance(data,list): raise PolicyError('expected array')
    from .security import atomic,write_json
    import tempfile
    normalized=json.dumps(data,indent=2)+'\n'
    manifest={'schema':1,'source':source,'version':version,'published_at':published_at,'sha256':hashlib.sha256(normalized.encode('utf-8')).hexdigest(),'authenticity':'Operator-supplied provenance; unsigned hash is not publisher authentication','coverage':'Exact enumerated versions only; version ranges not inferred'}
    with tempfile.TemporaryDirectory() as temp:
        candidate=Path(temp)/'candidate.json';atomic(candidate,normalized);write_json(candidate.with_suffix('.manifest.json'),manifest)
        Dataset(candidate,max_age_days=365000)
    atomic(p,normalized);write_json(p.with_suffix('.manifest.json'),manifest)
