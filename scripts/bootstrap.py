"""Explicit setup only. Creates a dedicated venv and installs locked dependencies."""
import argparse,hashlib,json,os,platform,subprocess,sys,venv
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def environment_paths(root=ROOT,wsl=False):
    if wsl:
        key=hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]
        base=Path.home()/'.local/share/secaudit'/key
        return base/'venv',base/'runs'
    return root/'.venv',root/'runs'

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--offline',action='store_true')
    parser.add_argument('--wsl',action='store_true')
    args=parser.parse_args()
    if platform.system()!='Linux' or not (3,11)<=sys.version_info[:2]<(3,15):
        raise SystemExit('Use Python 3.11–3.14 on Linux or the Windows WSL2 launcher.')
    env,output=environment_paths(wsl=args.wsl)
    env.parent.mkdir(parents=True,exist_ok=True)
    if env.is_symlink(): raise SystemExit('Refusing a symlink virtual environment.')
    if env.exists() and not (env/'pyvenv.cfg').is_file(): raise SystemExit('Environment directory exists but is not a virtual environment.')
    print('Creating/updating virtual environment: '+str(env),flush=True)
    venv.EnvBuilder(with_pip=True,clear=False,symlinks=True).create(env)
    python=env/'bin/python'
    requirements=ROOT/'requirements.lock'
    packages=[line for line in requirements.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if packages:
        command=[str(python),'-m','pip','--disable-pip-version-check','install','--require-hashes','-r',str(requirements)]
        if args.offline: command+=['--no-index','--find-links',str(ROOT/'wheelhouse')]
        else: command+=['--index-url','https://pypi.org/simple']
        subprocess.run(command,check=True,cwd=ROOT)
    else:
        print('Core has no third-party Python dependencies; no unnecessary downloads.',flush=True)
    import shlex
    launcher=env/'bin/secaudit'
    launcher.write_text('#!/bin/sh\nexec '+shlex.quote(str(python))+' '+shlex.quote(str(ROOT/'scripts/launch.py'))+' \"$@\"\n',encoding='utf-8')
    launcher.chmod(0o700)
    # State is written only after successful provisioning. No secrets are stored.
    state={'schema':1,'python':str(python.resolve()),'venv_python':str(python),'output':str(output),'backend':'wsl2' if args.wsl else 'linux'}
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(mode='w',encoding='utf-8',dir=ROOT,delete=False) as f:
        json.dump(state,f,indent=2);name=f.name
    os.replace(name,ROOT/'.setup-state.json')
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    print('Running mandatory preflight...',flush=True)
    result=subprocess.run([str(python),'-m','secaudit','doctor','--config','config/offline.json','--output',str(output)],cwd=ROOT)
    if result.returncode: raise SystemExit(result.returncode)
    print('Setup complete. Use run.cmd on Windows or ./run.sh on Linux.')

if __name__=='__main__': main()
