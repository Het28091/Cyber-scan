"""Validate integrity and declared provenance of expanded-release acceptance.

Unsigned records require a trusted operator/CI source; this is not an authenticity
check or proof that an attestation is truthful. Records are created after the source
commit and supplied separately from that commit's checkout.
"""
import hashlib
import json
import re
from pathlib import Path,PurePosixPath
from .security import PolicyError

GATES={
    'original_brief':'operator-attestation','non_ai':'linux-acceptance',
    'local_ai':'real-provider','api_ai':'real-provider',
    'dashboard':'browser-acceptance','target_workflows':'linux-acceptance',
    'target_browser':'browser-acceptance','detection_frameworks':'operator-attestation',
    'owner_machine':'operator-attestation','linux_ci':'ci-acceptance',
}


def read_json(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size>5_000_000:raise PolicyError('acceptance artifact missing, linked or oversized')
    try:
        raw=path.read_bytes();value=json.loads(raw)
    except (ValueError,UnicodeError,OSError):raise PolicyError('invalid acceptance JSON') from None
    if not isinstance(value,dict):raise PolicyError('acceptance artifact must be an object')
    return value,hashlib.sha256(raw).hexdigest()


def evidence_path(root,name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name:raise PolicyError('invalid acceptance evidence path')
    relative=PurePosixPath(name)
    if relative.is_absolute() or any(p in ('','.','..') for p in name.split('/')):raise PolicyError('acceptance evidence must remain inside its directory')
    candidate=root
    for part in relative.parts:
        candidate=candidate/part
        if candidate.is_symlink():raise PolicyError('linked acceptance evidence forbidden')
    if not candidate.resolve().is_relative_to(root.resolve()):raise PolicyError('acceptance evidence escaped its directory')
    return candidate


def verify(manifest_path,commit,version):
    if not isinstance(commit,str) or not re.fullmatch(r'[a-f0-9]{40}',commit):raise PolicyError('full source commit required')
    path=Path(manifest_path);manifest,digest=read_json(path)
    if type(manifest.get('schema')) is not int or manifest['schema']!=1 or manifest.get('source_commit')!=commit or manifest.get('app_version')!=version:raise PolicyError('acceptance manifest source/version mismatch')
    gates=manifest.get('gates')
    if not isinstance(gates,dict) or set(gates)!=set(GATES):raise PolicyError('every expanded acceptance gate must be present')
    seen=set();verified={}
    for name,kind in GATES.items():
        record=gates[name]
        if not isinstance(record,dict) or set(record)!={'status','evidence','sha256'} or record['status']!='PASS':raise PolicyError(name+': acceptance is not PASS')
        if not isinstance(record['sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',record['sha256']):raise PolicyError(name+': evidence digest required')
        evidence=evidence_path(path.parent,record['evidence'])
        if evidence.resolve() in seen:raise PolicyError('each acceptance gate requires its own evidence record')
        seen.add(evidence.resolve());report,actual=read_json(evidence)
        if actual!=record['sha256']:raise PolicyError(name+': evidence checksum mismatch')
        if any(report.get(k)!=v for k,v in {'gate':name,'status':'PASS','kind':kind,'source_commit':commit,'app_version':version}.items()):raise PolicyError(name+': evidence provenance mismatch or fixture-only result')
        if report.get('unresolved_requirements')!=[]:raise PolicyError(name+': unresolved acceptance requirements must be explicitly empty')
        checks=report.get('checks')
        if not isinstance(checks,list) or not 1<=len(checks)<=200 or any(not isinstance(c,str) or not c.strip() or len(c)>1000 for c in checks):raise PolicyError(name+': completed checks required')
        if kind=='operator-attestation' and (not isinstance(report.get('reviewer'),str) or not report['reviewer'].strip()):raise PolicyError(name+': operator reviewer required')
        if name in ('local_ai','api_ai'):
            expected='local-ai' if name=='local_ai' else 'connected-ai'
            if report.get('mode')!=expected or report.get('real_provider_verified') is not True or not isinstance(report.get('provider_identity'),str) or not report['provider_identity'].strip():raise PolicyError(name+': real provider identity and attestation required')
        if name=='non_ai' and report.get('modes_verified')!=['offline','internet']:raise PolicyError('both non-AI modes require independent verification')
        if kind in ('linux-acceptance','browser-acceptance','ci-acceptance') and report.get('platform')!='Linux':raise PolicyError(name+': Linux acceptance required')
        if name=='linux_ci' and (report.get('conclusion')!='success' or not isinstance(report.get('run_url'),str) or not re.fullmatch(r'https://github\.com/[^/]+/[^/]+/actions/runs/[0-9]+',report['run_url'])):raise PolicyError('successful CI run reference required')
        verified[name]=actual
    return {'status':'PASS','source_commit':commit,'app_version':version,'manifest_sha256':digest,'gates':verified,
            'authenticity':'Unsigned evidence requires trusted operator/CI provenance; validation does not prove a report is truthful.'}
