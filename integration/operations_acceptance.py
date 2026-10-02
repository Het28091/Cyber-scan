"""Owned-fixture backup/restore, v1.1.0 upgrade/rollback and reference measurements."""
import io
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tarfile
import tempfile
import time
from secaudit.maintenance import backup,restore,inventory
from secaudit.review import Reviews
from secaudit.profiles import Profiles

ROOT=Path(__file__).resolve().parents[1]


def command(root,*args):
    env=dict(os.environ,PYTHONPATH=str(root))
    result=subprocess.run([sys.executable,'-m','secaudit',*args],cwd=root,env=env,capture_output=True,text=True,timeout=120)
    if result.returncode:raise AssertionError('Fixture CLI failed: '+result.stderr)
    return result.stdout


def main():
    previous=subprocess.check_output(['git','rev-parse','v1.1.0^{commit}'],cwd=ROOT,text=True).strip()
    current=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    result={'source_commit':current,'previous_commit':previous,'platform':platform.platform(),
        'python':platform.python_version(),'cpu_count':os.cpu_count(),'measurements':[],
        'memory_total_bytes':os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')}
    with tempfile.TemporaryDirectory(prefix='secaudit-operations-') as temp:
        root=Path(temp);old=root/'previous';old.mkdir()
        archive=subprocess.check_output(['git','archive',previous],cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(old,filter='data')
        evidence=root/'runs'
        output=json.loads(command(old,'scan','--config',str(old/'config/offline.json'),'--source',str(old/'demo/source'),'--output',str(evidence)))
        ident=output['id'] if 'id' in output else Path(output['reports']).name
        original=json.loads((evidence/ident/'run.json').read_text())['findings']
        before=inventory(evidence);backup(evidence,root/'before-upgrade')
        command(ROOT,'export-reports',ident,'--output',str(evidence))
        assert json.loads((evidence/ident/'run.json').read_text())['findings']==original
        profiles=Profiles(evidence)
        try:profiles.save({'name':'upgrade fixture','configuration':{'source':'demo/source','preset':'offline'}})
        finally:profiles.close()
        reviews=Reviews(evidence)
        try:
            reviews.update(ident,original[0]['id'],{'revision':0,'status':'REMEDIATION_PENDING','note':'Owned upgrade fixture','owner':'fixture operator','due_date':'2026-10-14'})
        finally:reviews.close()
        command(ROOT,'export-reports',ident,'--output',str(evidence))
        backup(evidence,root/'after-upgrade');restore(root/'after-upgrade',root/'restored')
        assert inventory(evidence)==inventory(root/'restored')
        reviews=Reviews(root/'restored')
        try:assert reviews.snapshot(ident)['decisions'][original[0]['id']]['due_date']=='2026-10-14'
        finally:reviews.close()
        restore(root/'before-upgrade',root/'rollback')
        assert inventory(root/'rollback')==before
        # Roll back both application and the pre-upgrade data copy, never current evidence.
        command(old,'resume',ident,'--output',str(root/'rollback'))
        assert json.loads((root/'rollback'/ident/'run.json').read_text())['findings']==original
        for count in (10,100,1000):
            source=root/f'source-{count}';source.mkdir()
            for n in range(count):(source/f'clean{n}.py').write_text('value = 1\n')
            started=time.monotonic()
            output=json.loads(command(ROOT,'scan','--config',str(ROOT/'config/offline.json'),'--source',str(source),'--output',str(root/f'measured-{count}')))
            folder=Path(output['reports'])
            result['measurements'].append({'files':count,'seconds':round(time.monotonic()-started,3),
                'report_bytes':sum(p.stat().st_size for p in folder.iterdir() if p.is_file())})
        result['children_peak_rss_kib']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    result.update(status='PASS',checks=['old release scan','upgrade export preserves findings','reviews and profiles saved',
        'byte-identical verified restore','old application with pre-upgrade rollback copy'],
        limitations=['Synthetic workloads only; no owner-approved performance budget yet',
            'Child peak RSS is the maximum over this exercise, not per-workload profiling',
            'Quiescent backup required; not crash-consistent live backup or in-place data downgrade'])
    path=ROOT/'artifacts/checkpoints/independent/operations.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
