"""Prepare three separate owner-run configurations. No scans, probes or API calls."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import shlex

from secaudit.config import Config,load
from secaudit.security import PolicyError,Scope,canonical


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,help='Owned source directory for offline and API-assisted runs')
    parser.add_argument('--target',required=True,help='Owner-authorized web URL')
    parser.add_argument('--scope',required=True,help='Reviewed scope JSON with current IP pins')
    parser.add_argument('--api-config',required=True,help='Prepared connected-ai config with environment-variable credential reference')
    parser.add_argument('--destination',required=True,help='New private directory outside the scanned source')
    args=parser.parse_args()
    source=Path(args.source).resolve();destination=Path(args.destination).resolve()
    if not source.is_dir():raise PolicyError('owned source directory unavailable')
    if destination==source or destination.is_relative_to(source):raise PolicyError('mode workspace must be outside the scanned source')
    if destination.exists():raise PolicyError('mode workspace must be a new directory')
    scope_data=json.loads(Path(args.scope).read_text())
    scope=Scope(scope_data,allow_public=True)
    origin,path,_,_=canonical(args.target)
    def matches(entries):return any(origin==o and (p=='/' or path==p or path.startswith(p.rstrip('/')+'/')) for o,p in entries)
    if not matches(scope.allow) or matches(scope.deny):raise PolicyError('target is outside the supplied scope')
    # Validation opt-in only, restored immediately; this tool never creates a provider.
    previous=os.environ.get('SECAUDIT_EXPERIMENTAL_AI')
    os.environ['SECAUDIT_EXPERIMENTAL_AI']='1'
    try:
        api=load(args.api_config)
        if api.mode!='connected-ai':raise PolicyError('prepared API configuration must use connected-ai mode')
        api.source=str(source);api.target='';api.target_workflow={}
        api.modules=['source','secrets','config'];api.output=str(destination/'api-runs')
        api.ai.failure_policy='required';api.validate()
    finally:
        if previous is None:os.environ.pop('SECAUDIT_EXPERIMENTAL_AI',None)
        else:os.environ['SECAUDIT_EXPERIMENTAL_AI']=previous
    offline=Config(source=str(source),modules=['source','secrets','config','dependencies','openapi'],output=str(destination/'offline-runs')).validate()
    web=Config(mode='internet',target=args.target,scope=str(destination/'scope.json'),modules=['web'],strict=True,output=str(destination/'web-runs')).validate()
    destination.mkdir(parents=True,mode=0o700)
    for name,data in [('offline.json',asdict(offline)),('web.json',asdict(web)),('api.json',asdict(api)),('scope.json',scope_data)]:
        file=destination/name
        with file.open('x',encoding='utf-8') as stream:json.dump(data,stream,indent=2);stream.write('\n')
        file.chmod(0o600)
    launcher=shlex.quote(str(Path(__file__).resolve().parents[1]/'run.sh'))
    commands=[]
    for name in ['offline','web','api']:
        prefix='SECAUDIT_EXPERIMENTAL_AI=1 ' if name=='api' else ''
        commands.append(prefix+'bash '+launcher+' scan --config '+shlex.quote(str(destination/(name+'.json'))))
    instructions='\n'.join(['# Owner-run mode workspace','',
        'Prepared only: no scan, network probe, inference or acceptance has run.',
        'Each mode writes into its own evidence directory.',
        'API mode scans the supplied source only and requires the configured credential environment.',
        'Confirm free-only account settings before running API mode; zero cost_ceiling does not enforce free billing.',
        'Review scope, provider pins, disclosure and generated configs before running.',
        'No credentials were read from the environment or written by this tool.','',
        '```sh',*commands,'```','',
        'Record observed outcomes using docs/OWNER_TEST_SHEET.md. No result is pre-approved.',''])
    readme=destination/'README.md';readme.write_text(instructions,encoding='utf-8');readme.chmod(0o600)
    print('Prepared owner-run configurations; NOT TESTED. Instructions: '+str(readme))


if __name__=='__main__':
    try:main()
    except (PolicyError,OSError,ValueError):raise SystemExit('Preparation failed. Check local paths, configuration and scope; no scan or provider request was made.')
