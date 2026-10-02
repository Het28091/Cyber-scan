"""Quiescent local backup/restore. Never merges into an existing evidence directory."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from .security import PolicyError,write_json
from .models import now

MANIFEST='backup-manifest.json'
LIMIT_FILES=100000
LIMIT_BYTES=10*1024**3


def inventory(root):
    result={};total=0
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise PolicyError('backup/restore refuses symbolic links')
        if path.is_dir():continue
        if not path.is_file():raise PolicyError('backup/restore requires regular files')
        name=path.relative_to(root).as_posix()
        if name in (MANIFEST,'.jobs/dashboard.lock'):continue
        size=path.stat().st_size;total+=size
        if len(result)>=LIMIT_FILES or total>LIMIT_BYTES:raise PolicyError('backup exceeds 100000 files or 10 GiB')
        digest=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
        result[name]={'bytes':size,'sha256':digest.hexdigest()}
    return result


def validate_stopped(root):
    from .report_state import publication
    for path in (root/'.jobs').glob('*.json'):
        if path.name.endswith('.config.json'):raise PolicyError('remove orphan execution inputs using dashboard recovery before backup')
        job=json.loads(path.read_text())
        if job.get('status') in ('QUEUED','RUNNING'):raise PolicyError('stop and recover active jobs before backup')
    for folder in root.iterdir():
        if folder.is_dir() and len(folder.name)==32:
            state=publication(folder)
            if state and state['status']!='READY':raise PolicyError('refresh incomplete reports before backup')
    for name in ('runs.sqlite3','reviews.sqlite3','profiles.sqlite3'):
        path=root/name
        if not path.exists():continue
        if path.is_symlink():raise PolicyError('linked database refused')
        db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        try:
            if db.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise PolicyError('database integrity check failed')
            if db.execute('PRAGMA user_version').fetchone()[0]>1:raise PolicyError('database schema is newer than this application')
            if name=='runs.sqlite3' and db.execute("SELECT COUNT(*) FROM runs WHERE status='RUNNING'").fetchone()[0]:
                raise PolicyError('recover stopped CLI assessments before backup')
        finally:db.close()


def paths(source,destination):
    if Path(source).is_symlink() or Path(destination).is_symlink():raise PolicyError('linked maintenance paths refused')
    source=Path(source).resolve();destination=Path(destination).resolve()
    if not source.is_dir() or destination.exists():raise PolicyError('source must exist and destination must be new')
    if destination.is_relative_to(source) or source.is_relative_to(destination):raise PolicyError('source and destination must be separate directories')
    if not destination.parent.is_dir():raise PolicyError('destination parent must already exist')
    return source,destination


def copy_files(source,stage,entries):
    for name in entries:
        output=stage/name;output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        shutil.copyfile(source/name,output);output.chmod(0o600)


def backup(source,destination):
    import fcntl
    source,destination=paths(source,destination)
    if (source/'.jobs').is_symlink():raise PolicyError('linked job directory refused')
    (source/'.jobs').mkdir(exist_ok=True,mode=0o700)
    fd=os.open(source/'.jobs/dashboard.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise PolicyError('stop the dashboard before backup') from None
        entries=inventory(source);validate_stopped(source)
        with tempfile.TemporaryDirectory(prefix='.secaudit-backup-',dir=destination.parent) as temp:
            stage=Path(temp)/'snapshot';stage.mkdir(mode=0o700)
            copy_files(source,stage,entries)
            if inventory(stage)!=entries or inventory(source)!=entries:raise PolicyError('source changed during backup; stop all writers and retry')
            write_json(stage/MANIFEST,{'schema':1,'created_at':now(),'application_version':__import__('secaudit').__version__,'files':entries,
                'limitation':'Local integrity snapshot, not encryption or an authenticity signature. Preserve the source application commit separately.'})
            if destination.exists():raise PolicyError('backup destination already exists')
            stage.rename(destination)
    return {'backup':str(destination),'files':len(entries),'bytes':sum(v['bytes'] for v in entries.values())}


def restore(source,destination):
    source,destination=paths(source,destination)
    manifest=source/MANIFEST
    if manifest.is_symlink() or manifest.stat().st_size>30_000_000:raise PolicyError('backup manifest unavailable')
    data=json.loads(manifest.read_text())
    if not isinstance(data,dict) or data.get('schema')!=1 or not isinstance(data.get('files'),dict):raise PolicyError('unsupported backup manifest')
    entries=inventory(source)
    if data['files']!=entries:raise PolicyError('backup integrity mismatch')
    # Names come only from a validated local tree, never from manifest path strings.
    with tempfile.TemporaryDirectory(prefix='.secaudit-restore-',dir=destination.parent) as temp:
        stage=Path(temp)/'restored';stage.mkdir(mode=0o700);copy_files(source,stage,entries)
        if inventory(stage)!=entries or inventory(source)!=entries:raise PolicyError('backup changed during restore')
        validate_stopped(stage)
        if destination.exists():raise PolicyError('restore destination already exists')
        stage.rename(destination)
    return {'restored':str(destination),'files':len(entries),'next':'Start the dashboard with --output pointing to the restored directory; original evidence is untouched.'}
