"""Prepare or publish an expanded release after exact-commit evidence and CI pass.

No testing is performed by this command. It verifies previously completed CI via
GitHub, then collects already built stable bundles. Publishing is explicit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import zipfile

from secaudit import __version__
from secaudit.release_gate import verify,evidence_path,read_json


def github(path):
    result=subprocess.run(['gh','api',path],capture_output=True,text=True,check=True,timeout=60)
    return json.loads(result.stdout)


def verify_ci(repository,run_id,commit):
    run=github(f'repos/{repository}/actions/runs/{run_id}')
    if (run.get('head_sha')!=commit or run.get('status')!='completed' or run.get('conclusion')!='success'
            or run.get('event') not in ('push','workflow_dispatch')
            or run.get('path')!='.github/workflows/test.yml'
            or run.get('head_repository',{}).get('full_name')!=repository):
        raise ValueError('CI must be the successful repository acceptance workflow for the exact source commit')
    attempt=run.get('run_attempt')
    if type(attempt) is not int or attempt<1:raise ValueError('CI attempt is unavailable')
    jobs=[]
    for page in range(1,11):
        batch=github(f'repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}').get('jobs')
        if not isinstance(batch,list):raise ValueError('CI jobs unavailable')
        jobs.extend(batch)
        if len(batch)<100:break
    else:raise ValueError('CI job listing exceeds bound')
    required={'test','live-acceptance','browser-acceptance','target-browser-acceptance','operations-acceptance','semgrep-acceptance'}
    required|={f'distribution-acceptance ({os_name}, {python})' for os_name in ('ubuntu-22.04','ubuntu-24.04') for python in ('3.11','3.12','3.13','3.14')}
    required|={f'inventory-acceptance ({tool})' for tool in ('syft','trivy')}
    for name in required:
        matches=[j for j in jobs if j.get('name')==name]
        if len(matches)!=1 or matches[0].get('conclusion')!='success' or matches[0].get('status')!='completed':
            raise ValueError('required CI job missing, duplicated or unsuccessful: '+name)
    return {'run_url':f'https://github.com/{repository}/actions/runs/{run_id}','run_attempt':attempt,'source_commit':commit,'required_jobs':sorted(required),'conclusion':'success'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit',required=True)
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--repository',required=True,help='GitHub owner/repository')
    parser.add_argument('--ci-run',required=True,type=int)
    parser.add_argument('--notes',required=True,help='Reviewed release-note file')
    parser.add_argument('--publish',action='store_true',help='Create and publish a new release; otherwise only collect local assets')
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',args.repository) or args.ci_run<1:parser.error('valid repository and CI run required')
    if not re.fullmatch(r'\d+\.\d+\.\d+',__version__):parser.error('stable publication requires a final numeric application version')
    root=Path(__file__).resolve().parents[1]
    if Path.cwd().resolve()!=root:parser.error('run from the source repository root')
    package=runpy.run_path(str(root/'scripts/package-release.py'))
    package['verify_source'](root,args.commit)
    acceptance=verify(args.manifest,args.commit,__version__)
    manifest,_=read_json(Path(args.manifest))
    record,_=read_json(evidence_path(Path(args.manifest).parent,manifest['gates']['linux_ci']['evidence']))
    ci=verify_ci(args.repository,args.ci_run,args.commit)
    if record['run_url']!=ci['run_url']:raise ValueError('acceptance record and verified CI run differ')
    notes=Path(args.notes)
    if notes.is_symlink() or not notes.is_file() or not 1<=notes.stat().st_size<=100000:raise ValueError('reviewed release notes required')
    repository=github(f'repos/{args.repository}')
    tag='v'+__version__
    # Git refs prevent reusing an existing release tag even if no release is listed.
    refs=github(f'repos/{args.repository}/git/matching-refs/tags/{tag}')
    if not isinstance(refs,list) or any(ref.get('ref')=='refs/tags/'+tag for ref in refs):raise ValueError('release tag exists or could not be checked; select a new version before acceptance')
    commit_info=github(f'repos/{args.repository}/commits/{args.commit}')
    if commit_info.get('sha')!=args.commit:raise ValueError('source commit is not available in the destination repository')
    if repository.get('archived'):raise ValueError('destination repository is archived')
    os.environ['GITHUB_SHA']=args.commit
    os.environ['SECAUDIT_ACCEPTANCE_MANIFEST']=str(Path(args.manifest).resolve())
    collector=runpy.run_path(str(root/'scripts/collect-release.py'))
    collector['main']()
    output=root/'release-assets'
    (output/'ci-verification.json').write_text(json.dumps(ci,indent=2)+'\n',encoding='utf-8')
    # Include the exact accepted envelopes alongside the local gate summary.
    with zipfile.ZipFile(output/'acceptance-records.zip','x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json',Path(args.manifest).read_bytes())
        for entry in manifest['gates'].values():
            archive.writestr(entry['evidence'],evidence_path(Path(args.manifest).parent,entry['evidence']).read_bytes())
    checksums=[]
    for path in sorted(output.iterdir()):
        if path.name=='SHA256SUMS':continue
        with path.open('rb') as stream:checksums.append(hashlib.file_digest(stream,'sha256').hexdigest()+'  '+path.name)
    (output/'SHA256SUMS').write_text('\n'.join(checksums)+'\n',encoding='ascii')
    if args.publish:
        assets=[str(p) for p in sorted(output.iterdir())]
        subprocess.run(['gh','release','create',tag,*assets,'--repo',args.repository,'--target',args.commit,'--title','Secaudit '+__version__,'--notes-file',str(notes),'--draft'],check=True,timeout=300)
        subprocess.run(['gh','release','edit',tag,'--repo',args.repository,'--draft=false','--latest'],check=True,timeout=60)
    print(json.dumps({'status':'PUBLISHED' if args.publish else 'PREPARED','tag':tag,'output':str(output),'acceptance':acceptance,'ci':ci}))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        print('Release blocked: '+(str(error) if isinstance(error,ValueError) else type(error).__name__+'; inspect trusted local inputs and GitHub access.'),file=sys.stderr)
        raise SystemExit(2)
