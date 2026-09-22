from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
import hashlib,json

def now(): return datetime.now(timezone.utc).isoformat()
@dataclass
class Finding:
    rule: str
    title: str
    asset: str
    description: str
    remediation: str
    severity: str='MEDIUM'
    confidence: str='MEDIUM'
    line: int=0
    scanner: str='secaudit-builtins'
    scanner_version: str='0.6.0'
    evidence: list=field(default_factory=list)
    timestamp: str=field(default_factory=now)
    validation_status: str='NEEDS MANUAL REVIEW'
    role: str|None=None
    impact: str='Potential application or data exposure; actual exploitability requires review.'
    reproduction: str='Inspect the referenced location in an authorized local copy.'
    retest: str='Apply remediation and repeat this check; manually verify the affected workflow.'
    mappings: list=field(default_factory=list)
    cvss: dict|None=None
    provenance: list=field(default_factory=list)
    @property
    def fingerprint(self): return hashlib.sha256(json.dumps([self.rule,self.asset,self.line,self.role,self.description],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
    def to_dict(self): return dict(asdict(self),id=self.fingerprint[:32],fingerprint=self.fingerprint)

def dedup(findings):
    out={}
    for f in findings:
        key=f.fingerprint
        if key not in out: out[key]=f
        else:
            out[key].evidence=list(dict.fromkeys(out[key].evidence+f.evidence))
            out[key].provenance+=f.provenance or [{'scanner':f.scanner,'rule':f.rule,'version':f.scanner_version}]
    return list(out.values())
