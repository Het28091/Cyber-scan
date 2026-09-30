"""Create NOT TESTED acceptance records or seal reviewed records into a manifest."""
import argparse
import json
from pathlib import Path
import re
from secaudit import __version__
from secaudit.release_gate import GATES,read_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['init','seal'])
    parser.add_argument('--commit',required=True)
    parser.add_argument('--directory',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[a-f0-9]{40}',args.commit):parser.error('full source commit required')
    folder=Path(args.directory)
    if args.action=='init':
        folder.mkdir(parents=True,exist_ok=False,mode=0o700)
        for gate,kind in GATES.items():
            record={'gate':gate,'kind':kind,'status':'NOT TESTED','source_commit':args.commit,'app_version':__version__,'checks':[],
                    'unresolved_requirements':['Complete the documented acceptance for this exact commit; retain real supporting evidence.']}
            if kind=='operator-attestation':record['reviewer']=''
            if kind in ('linux-acceptance','browser-acceptance','ci-acceptance'):record['platform']=''
            if gate in ('local_ai','api_ai'):record.update(mode='local-ai' if gate=='local_ai' else 'connected-ai',real_provider_verified=False,provider_identity='')
            if gate=='non_ai':record['modes_verified']=[]
            if gate=='linux_ci':record.update(conclusion='NOT TESTED',run_url='')
            (folder/(gate+'.json')).write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    else:
        if folder.is_symlink() or not folder.is_dir():parser.error('record directory unavailable')
        manifest={'schema':1,'source_commit':args.commit,'app_version':__version__,'gates':{}}
        for gate,kind in GATES.items():
            name=gate+'.json';record,digest=read_json(folder/name)
            if record.get('source_commit')!=args.commit or record.get('app_version')!=__version__ or record.get('gate')!=gate or record.get('kind')!=kind:
                parser.error('record provenance mismatch: '+gate)
            manifest['gates'][gate]={'status':record.get('status','NOT TESTED'),'evidence':name,'sha256':digest}
        # Never overwrite an existing seal. A new source commit needs a new directory.
        with (folder/'manifest.json').open('x',encoding='utf-8') as stream:json.dump(manifest,stream,indent=2);stream.write('\n')
    print('Created NOT TESTED records.' if args.action=='init' else 'Sealed recorded statuses; this does not mark acceptance PASS. Run release-check separately.')


if __name__=='__main__':main()
