"""Full owned source scan and real queue drain; timings are observations, not SLAs."""
import json
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
from secaudit.jobs import Jobs

ROOT=Path(__file__).resolve().parents[1]


def main():
    result={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'python':platform.python_version(),'platform':platform.platform(),'checks':[]}
    with tempfile.TemporaryDirectory(prefix='secaudit-load-') as temp:
        root=Path(temp);source=root/'source';source.mkdir()
        for n in range(4999):(source/f'clean{n}.py').write_text('value = 1\n')
        started=time.monotonic()
        process=subprocess.run([sys.executable,'-m','secaudit','scan','--config',str(ROOT/'config/offline.json'),
            '--source',str(source),'--output',str(root/'runs')],cwd=ROOT,capture_output=True,text=True,timeout=90)
        summary=json.loads(process.stdout)
        run=json.loads((Path(summary['reports'])/'run.json').read_text())
        result['checks'].append({'name':'4999-file full assessment','status':summary['status'],
            'seconds':round(time.monotonic()-started,3),'assets':len(run['assets']),
            'report_bytes':sum(p.stat().st_size for p in Path(summary['reports']).iterdir() if p.is_file()),
            'returncode':process.returncode})
        small=root/'small';small.mkdir();(small/'owned.py').write_text('value = 1\n')
        jobs=Jobs(root/'queue');started=time.monotonic()
        try:
            admitted=[jobs.submit({'source':str(small),'preset':'offline'})['id'] for _ in range(10)]
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                records=[jobs.detail(ident) for ident in admitted]
                if all(j['status'] not in ('QUEUED','RUNNING') for j in records):break
                time.sleep(.05)
            result['checks'].append({'name':'ten real queued source assessments',
                'seconds':round(time.monotonic()-started,3),'statuses':[j['status'] for j in records]})
        finally:jobs.close()
        result['peak_child_rss_kib']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        passed=process.returncode==0 and len(run['assets'])==4999 and all(j['status']=='COMPLETED' for j in records)
    result.update(status='PASS' if passed else 'FAIL',limitations=['Owned clean Python files only; not a universal scanner performance budget',
        'Default 60-second scan timeout unchanged; owner hardware/budget approval pending',
        'RSS is cumulative child maximum, not per-job profiling; no AI or target traffic'])
    path=ROOT/'artifacts/checkpoints/independent/load.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n')
    print('::notice::Owned load evidence: '+json.dumps(result))
    if not passed:raise SystemExit(1)


if __name__=='__main__':main()
