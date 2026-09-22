"""Small reviewed mapping set, not an organizational compliance assessment."""
from pathlib import Path
import json,hashlib

from importlib.resources import files
DATA=files('secaudit').joinpath('data/frameworks.json')
def apply_mappings(run):
    payload=DATA.read_bytes();snapshot=json.loads(payload)
    for f in run['findings']:
        maps=[{'framework':'NIST CSF','version':'2.0','control':'ID.RA-01','status':'NEEDS MANUAL REVIEW','rationale':'Candidate vulnerability evidence supports identification; validation and organizational implementation remain manual.'}]
        maps+=[dict(x,status='NEEDS MANUAL REVIEW') for x in snapshot['rules'].get(f['rule'],[])]
        f['mappings']=maps
    run['framework_snapshot']={'version':snapshot['version'],'reviewed_at':snapshot['reviewed_at'],'sha256':hashlib.sha256(payload).hexdigest(),'sources':snapshot['sources'],'limitation':'Reviewed subset only; mappings are related evidence, not certification or control pass/fail.'}
