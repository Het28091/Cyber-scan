"""Run the installed environment; never provision during assessment."""
import json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PATH_FLAGS={'--source','--target','--archive','--scope','--output','--config','--destination'}

def convert_paths(args,convert):
    # Only local-path arguments are translated. URLs, provider identifiers and other values remain data.
    out=list(args)
    for i,value in enumerate(out):
        if i and out[i-1] in PATH_FLAGS-{'--target'} and value.startswith('\\\\'):
            raise SystemExit('UNC paths are unsupported; use a local drive-letter path.')
        if i and out[i-1] in PATH_FLAGS-{'--target'} and re.match(r'^[A-Za-z]:[\\/]',value): out[i]=convert(value)
        elif i and out[i-1] in ('verify','install') and re.match(r'^[A-Za-z]:[\\/]',value): out[i]=convert(value)
        elif value.startswith('--') and '=' in value:
            key,v=value.split('=',1)
            if key in PATH_FLAGS-{'--target'} and re.match(r'^[A-Za-z]:[\\/]',v): out[i]=key+'='+convert(v)
    return out

def main():
    try: state=json.loads((ROOT/'.setup-state.json').read_text(encoding='utf-8'))
    except (OSError,ValueError): raise SystemExit('Run setup.cmd on Windows or bash setup.sh on Linux first.')
    python=Path(state['venv_python'])
    if not python.exists(): raise SystemExit('Virtual environment missing. Rerun initial setup.')
    args=sys.argv[1:] or ['dashboard']
    if state['backend']=='wsl2':
        args=convert_paths(args,lambda p:subprocess.check_output(['wslpath','-u',p],text=True).strip())
    if args[0] in ('doctor','scan','dashboard','resume') and not any(x=='--output' or x.startswith('--output=') for x in args): args+=['--output',state['output']]
    if args==['test']: command=[str(python),'-m','unittest','discover','-s','tests','-v']
    elif args==['demo-server']: command=[str(python),'demo/server.py']
    elif args==['reports']:
        print(state['output']);return
    else: command=[str(python),'-m','secaudit',*args]
    os.chdir(ROOT)
    os.execv(str(python),command)

if __name__=='__main__': main()
