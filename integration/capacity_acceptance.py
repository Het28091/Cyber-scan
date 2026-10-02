"""Measure default source traversal boundaries on owned files, without providers."""
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import time
from secaudit.config import Config
from secaudit.scanners import files
from secaudit.security import PolicyError

ROOT=Path(__file__).resolve().parents[1]


def main():
    rows=[];cfg=Config()
    with tempfile.TemporaryDirectory(prefix='secaudit-capacity-') as temp:
        root=Path(temp);counted=root/'count';counted.mkdir()
        for n in range(cfg.max_files+1):(counted/f'{n:05d}.txt').write_text('owned fixture\n')
        def check(label,source,expected,accepted):
            started=time.monotonic();observed=0;status='PASS';reason=''
            try:
                for _ in files(source,cfg):observed+=1
            except PolicyError as error:status='REJECTED';reason=str(error)
            assert status==expected,(label,status,reason)
            assert observed==accepted,(label,observed,accepted)
            rows.append({'case':label,'result':status,'files_yielded':observed,
                'seconds':round(time.monotonic()-started,4),'reason':reason})
        check('default file count plus one',counted,'REJECTED',cfg.max_files)
        (counted/f'{cfg.max_files:05d}.txt').unlink()
        check('exact default file count',counted,'PASS',cfg.max_files)
        large=root/'bytes';large.mkdir();path=large/'owned.txt'
        path.write_bytes(b'x'*cfg.max_file_bytes)
        check('exact default per-file bytes',large,'PASS',1)
        with path.open('ab') as stream:stream.write(b'x')
        check('default per-file bytes plus one',large,'REJECTED',0)
        path.unlink()
        for n in range(cfg.max_total_bytes//cfg.max_file_bytes):
            (large/f'{n:03d}.txt').write_bytes(b'x'*cfg.max_file_bytes)
        check('exact default total bytes',large,'PASS',50)
        (large/'last.txt').write_bytes(b'x')
        check('default total bytes plus one',large,'REJECTED',50)
    result={'status':'PASS','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'platform':platform.platform(),'python':platform.python_version(),'checks':rows,
        'limits':{'max_files':cfg.max_files,'max_file_bytes':cfg.max_file_bytes,'max_total_bytes':cfg.max_total_bytes},
        'limitations':['Traversal only; not whole-assessment throughput, reporting or target latency',
            'Configured limits remain unchanged; owner-approved operating budgets still required']}
    path=ROOT/'artifacts/checkpoints/independent/capacity.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
