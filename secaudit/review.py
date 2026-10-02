"""Operator decisions are append-only records, separate from scanner evidence."""
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit
from datetime import date,datetime
from .models import now
from .security import PolicyError,redact

STATES=('OPEN','CONFIRMED','FALSE_POSITIVE','ACCEPTED_RISK','REMEDIATION_PENDING','RETEST_REQUESTED','RESOLVED')
TERMINAL={'COMPLETED_WITH_LIMITATIONS','FAILED','CANCELLED','INTERRUPTED'}


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{32}',value): raise PolicyError('invalid evidence identifier')
    return value


def load_run(root,ident):
    folder=Path(root)/identifier(ident)
    path=folder/'run.json'
    if folder.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size>10_000_000: raise PolicyError('saved run unavailable')
    try:run=json.loads(path.read_text(encoding='utf-8'))
    except (OSError,ValueError):raise PolicyError('saved run unavailable') from None
    if not isinstance(run,dict) or run.get('id')!=ident or run.get('status') not in TERMINAL or not isinstance(run.get('findings'),list): raise PolicyError('a terminal saved run is required')
    return run


def context(cfg):
    target=urlsplit(cfg.target)
    return {'version':1,'source_root':str(Path(cfg.source).resolve()) if cfg.source else '',
            'target':target.scheme+'://'+target.netloc+target.path if cfg.target else '',
            'modules':sorted(cfg.modules),'scanners':cfg.scanners,
            'source_limits':[cfg.max_files,cfg.max_file_bytes,cfg.max_total_bytes],
            'target_workflow_sha256':hashlib.sha256(json.dumps(cfg.target_workflow,sort_keys=True).encode()).hexdigest()}


def compare(before,after):
    """Comparison describes saved observations, never certifies remediation."""
    if before['id']==after['id']:raise PolicyError('choose a different retest run')
    same=bool(before.get('assessment_context')) and before.get('assessment_context')==after.get('assessment_context')
    try:
        start=datetime.fromisoformat(after['started']);finished=datetime.fromisoformat(before['finished'])
        chronological=bool(start.tzinfo and finished.tzinfo and start>=finished)
    except (KeyError,ValueError,TypeError):chronological=False
    complete=before.get('status')==after.get('status')=='COMPLETED_WITH_LIMITATIONS'
    old={f['id']:f for f in before['findings']};new={f['id']:f for f in after['findings']}
    rows=[]
    coverage=after.get('coverage',[])
    limited=any(c.get('status')=='NOT TESTED' or c.get('execution_complete') is False for c in coverage) or not coverage
    for ident,finding in old.items():
        if ident in new:status='OBSERVED_AGAIN';related=[ident]
        else:
            related=[f['id'] for f in new.values() if all(f.get(k)==finding.get(k) for k in ('rule','asset','role'))]
            status='POSSIBLY_MOVED' if related else 'NOT_OBSERVED' if same and chronological and complete and not limited else 'NOT_RETESTED'
        rows.append({'finding_id':ident,'rule':finding['rule'],'status':status,'related_findings':related})
    rows.extend({'finding_id':ident,'rule':f['rule'],'status':'NEW_OBSERVATION','related_findings':[]} for ident,f in new.items() if ident not in old)
    return {'baseline_run':before['id'],'retest_run':after['id'],'same_context':same,'chronological':chronological,'rows':rows,
            'limitation':'Missing observations are not proof of remediation. Partial coverage, moved code and changed rules require operator review; no status is changed automatically.'}


class Reviews:
    def __init__(self,root):
        self.root=Path(root)
        path=self.root/'reviews.sqlite3'
        if path.is_symlink():raise PolicyError('symlink review database refused')
        self.db=sqlite3.connect(path,timeout=10)
        from .database import guard_schema
        guard_schema(self.db)
        path.chmod(0o600)
        with self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS decisions(run_id TEXT NOT NULL,finding_id TEXT NOT NULL,revision INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(run_id,finding_id,revision))')

    def close(self):self.db.close()

    def snapshot(self,ident):
        run=load_run(self.root,ident)
        ids={f['id'] for f in run['findings']}
        rows=self.db.execute('SELECT finding_id,data FROM decisions WHERE run_id=? ORDER BY finding_id,revision',(ident,)).fetchall()
        history=[json.loads(raw) for finding,raw in rows if finding in ids]
        latest={entry['finding_id']:entry for entry in history}
        return {'run_id':ident,'decisions':latest,'history':history,'authority':'Local operator assertions; scanner evidence is unchanged.'}

    def update(self,ident,finding_id,data):
        identifier(finding_id)
        run=load_run(self.root,ident)
        if not any(f.get('id')==finding_id for f in run['findings']):raise PolicyError('finding does not belong to this run')
        if not isinstance(data,dict) or set(data)-{'status','note','owner','evidence','retest_run','revision','due_date'}:raise PolicyError('invalid review fields')
        status=data.get('status');note=data.get('note','');owner=data.get('owner','');evidence=data.get('evidence','');retest=data.get('retest_run','');revision=data.get('revision')
        if status not in STATES or type(revision) is not int or not 0<=revision<1000:raise PolicyError('invalid review status or revision')
        for value,limit in ((note,4000),(owner,120),(evidence,2000)):
            if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 and c not in '\n\t' for c in value):raise PolicyError('invalid review text')
        if not note.strip():raise PolicyError('a review rationale is required')
        due=data.get('due_date','')
        if not isinstance(due,str):raise PolicyError('invalid remediation due date')
        if due:
            try:parsed=date.fromisoformat(due)
            except ValueError:raise PolicyError('due date must use YYYY-MM-DD') from None
            if parsed.isoformat()!=due:raise PolicyError('due date must use YYYY-MM-DD')
        if status in ('CONFIRMED','FALSE_POSITIVE','ACCEPTED_RISK','RESOLVED') and not evidence.strip():raise PolicyError('record the reviewed evidence or verification reference')
        comparison=None
        if not isinstance(retest,str):raise PolicyError('invalid retest run')
        if retest:
            after=load_run(self.root,retest);comparison=compare(run,after)
        if status=='RESOLVED':
            if not comparison or not comparison['same_context'] or after['status']!='COMPLETED_WITH_LIMITATIONS':raise PolicyError('resolution requires a completed retest with matching assessment context')
            row=next(r for r in comparison['rows'] if r['finding_id']==finding_id)
            if row['status']!='NOT_OBSERVED':raise PolicyError('finding is still observed or was not sufficiently retested')
        safe=redact({'run_id':ident,'finding_id':finding_id,'revision':revision+1,'status':status,'note':note.strip(),'owner':owner.strip(),'due_date':due,'evidence':evidence.strip(),'retest_run':retest,'recorded_at':now(),'actor':'local-operator'})
        # Serialize revision checks and appends across independent CLI/API processes.
        try:
            self.db.execute('BEGIN IMMEDIATE')
            current=self.db.execute('SELECT COALESCE(MAX(revision),0) FROM decisions WHERE run_id=? AND finding_id=?',(ident,finding_id)).fetchone()[0]
            if current!=revision:raise PolicyError('review changed; reload before saving')
            self.db.execute('INSERT INTO decisions VALUES(?,?,?,?)',(ident,finding_id,revision+1,json.dumps(safe)))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise
        return safe


def with_reviews(root,run):
    """Attach a current review snapshot only when explicitly exporting reports."""
    if not (Path(root)/'reviews.sqlite3').exists():return run
    store=Reviews(root)
    try:return dict(run,operator_review=store.snapshot(run['id']))
    finally:store.close()
