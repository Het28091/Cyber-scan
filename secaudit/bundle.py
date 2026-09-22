"""Portable core plus optional offline PDF wheels. Never download during install."""
import json,platform,shutil,sys,zipapp,zipfile,subprocess,venv
from pathlib import Path
from .security import PolicyError,atomic,digest,write_json,extract_zip
from . import __version__

ALLOWED=['secaudit.pyz','source.zip','LICENSE','README.md','requirements.lock']
SOURCE_PATHS=['secaudit','scripts','config','demo/source','demo/server.py','tests','docs','setup.sh','run.sh','setup.cmd','run.cmd','Makefile','scope.json','requirements.lock','LICENSE','README.md']
def prepare(output,download_dependencies=False):
    out=Path(output)
    if out.exists(): raise PolicyError('bundle output must not already exist')
    out.mkdir(parents=True,mode=0o700)
    root=Path(__file__).resolve().parent.parent
    if not (root/'secaudit').is_dir(): raise PolicyError('prepare requires the source checkout')
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        stage=Path(temp)
        shutil.copytree(root/'secaudit',stage/'secaudit',ignore=shutil.ignore_patterns('__pycache__'))
        (stage/'__main__.py').write_text('from secaudit.cli import main\nraise SystemExit(main())\n')
        zipapp.create_archive(stage,out/'secaudit.pyz',interpreter='/usr/bin/env python3')
    with zipfile.ZipFile(out/'source.zip','w',zipfile.ZIP_DEFLATED) as z:
        for name in SOURCE_PATHS:
            path=root/name
            for f in sorted(path.rglob('*')) if path.is_dir() else [path]:
                if f.is_file() and not f.is_symlink() and '__pycache__' not in f.parts and f.suffix!='.pyc': z.write(f,f.relative_to(root))
    for name in ('LICENSE','README.md','requirements.lock'): shutil.copyfile(root/name,out/name)
    names=list(ALLOWED)
    if download_dependencies:
        wheelhouse=out/'wheelhouse';wheelhouse.mkdir()
        subprocess.run([sys.executable,'-m','pip','--disable-pip-version-check','download','--require-hashes','--only-binary=:all:','--dest',str(wheelhouse),'-r',str(root/'requirements.lock'),'--index-url','https://pypi.org/simple'],check=True)
        names += [p.relative_to(out).as_posix() for p in sorted(wheelhouse.glob('*.whl'))]
    manifest={'schema':2,'app_version':__version__,'python_min':'3.11','python_version':list(sys.version_info[:2]),'os':'Linux','architecture':platform.machine(),'prerequisites':['Python 3.11+ with venv/pip','system libseccomp2','matching Python minor version for optional wheels'],'provenance':'Built from local source; optional wheels verified against requirements.lock','authenticity':'Unsigned SHA-256 detects corruption, not publisher authenticity','pdf_wheels':download_dependencies,'files':{n:digest(out/n) for n in names}}
    write_json(out/'manifest.json',manifest)
    return manifest

def verify(bundle):
    b=Path(bundle)
    if b.is_symlink() or (b/'manifest.json').is_symlink(): raise PolicyError('bundle symlinks forbidden')
    m=json.loads((b/'manifest.json').read_text())
    if m.get('schema')!=2 or m.get('os')!=platform.system() or m.get('architecture')!=platform.machine() or sys.version_info<(3,11): raise PolicyError('incompatible bundle platform/schema')
    entries=m.get('files',{})
    if not isinstance(entries,dict) or not set(ALLOWED)<=set(entries): raise PolicyError('missing bundle files')
    for name,sha in entries.items():
        p=Path(name)
        if name not in ALLOWED and not (len(p.parts)==2 and p.parts[0]=='wheelhouse' and p.suffix=='.whl'): raise PolicyError('unexpected bundle files')
        if p.is_absolute() or '..' in p.parts or any((b/Path(*p.parts[:i])).is_symlink() for i in range(1,len(p.parts)+1)): raise PolicyError('bundle symlinks or traversal forbidden')
        if not (b/p).is_file() or digest(b/p)!=sha: raise PolicyError('bundle checksum mismatch')
    if m.get('pdf_wheels') and (m.get('python_version')!=list(sys.version_info[:2]) or not any(n.endswith('.whl') for n in entries)): raise PolicyError('wheel bundle requires matching Python minor version and wheel files')
    return m

def install(bundle,destination):
    m=verify(bundle);dest=Path(destination).resolve()
    if dest.exists(): raise PolicyError('install destination already exists')
    dest.mkdir(parents=True,mode=0o700)
    for name in ALLOWED: shutil.copyfile(Path(bundle)/name,dest/name)
    source=extract_zip(dest/'source.zip',dest/'app',100_000_000,10000)
    python=Path(sys.executable)
    if m.get('pdf_wheels'):
        venv.EnvBuilder(with_pip=True).create(dest/'venv');python=dest/'venv/bin/python'
        subprocess.run([str(python),'-m','pip','--disable-pip-version-check','install','--no-index','--find-links',str(Path(bundle).resolve()/'wheelhouse'),'--require-hashes','-r',str(dest/'requirements.lock')],check=True)
    import shlex
    atomic(dest/'secaudit','#!/bin/sh\ncd '+shlex.quote(str(source))+' || exit 1\nexec '+shlex.quote(str(python))+' -m secaudit "$@"\n')
    (dest/'secaudit').chmod(0o700)
    return {'installed':str(dest),'manifest':m}
