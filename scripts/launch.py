"""Run the installed environment; never provision during assessment."""
import json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    try: state=json.loads((ROOT/'.setup-state.json').read_text(encoding='utf-8'))
    except (OSError,ValueError): raise SystemExit('Run bash setup.sh first.')
    python=Path(state['venv_python'])
    if not python.exists(): raise SystemExit('Virtual environment missing. Rerun initial setup.')
    args=sys.argv[1:] or ['dashboard']
    if args[0] in ('doctor','scan','dashboard','resume') and not any(x=='--output' or x.startswith('--output=') for x in args): args+=['--output',state['output']]
    if args==['test']: command=[str(python),'-m','unittest','discover','-s','tests','-v']
    elif args==['demo-server']: command=[str(python),'demo/server.py']
    elif args==['reports']:
        print(state['output']);return
    else: command=[str(python),'-m','secaudit',*args]
    os.chdir(ROOT)
    os.execv(str(python),command)

if __name__=='__main__': main()
