"""Detect interrupted or tampered report publication without trusting mixed files."""
import hashlib
import json
from pathlib import Path
from .security import PolicyError

MANIFEST='report-publication.json'
GENERATED={'run.json','findings.json','assets.json','inventory.json','findings.csv',
    'coverage.csv','framework-mappings.csv','technical.md','technical.html',
    'executive.html','remediation-retest.md','findings.sarif','sbom.cdx.json',
    'external-sbom.cdx.json','technical.pdf','executive.pdf','pdf-unavailable.txt',
    'ai-suggestions.json','operator-review.json'}


def publication(directory):
    path=Path(directory)/MANIFEST
    if not path.exists() and not path.is_symlink():return None
    if path.is_symlink() or path.stat().st_size>20000:raise PolicyError('report publication record unavailable')
    try:
        value=json.loads(path.read_text())
        if value.get('schema')!=1 or value.get('status') not in ('INCOMPLETE','READY'):raise ValueError()
        if value['status']=='READY' and (not isinstance(value.get('sha256'),dict) or set(value['sha256'])-GENERATED):raise ValueError()
        return value
    except (ValueError,TypeError,AttributeError):raise PolicyError('invalid report publication record') from None


def read_report(directory,name):
    directory=Path(directory);before=publication(directory)
    if before and before['status']!='READY':raise PolicyError('report refresh incomplete; retry export before downloading')
    path=directory/name
    if path.is_symlink() or path.stat().st_size>30_000_000:raise PolicyError('report unavailable')
    data=path.read_bytes()
    if before and name in GENERATED and hashlib.sha256(data).hexdigest()!=before['sha256'].get(name):
        raise PolicyError('report snapshot integrity mismatch; regenerate from saved evidence')
    if publication(directory)!=before:raise PolicyError('report snapshot changed during download; retry')
    return data
