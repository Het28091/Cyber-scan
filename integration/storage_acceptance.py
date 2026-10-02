"""Actual ENOSPC recovery on an owned, 1 MiB Bubblewrap tmpfs; never fill host disk."""
import json
from pathlib import Path
import subprocess
import sys
import shlex

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def exercise():
    import errno
    from secaudit.reporting import reports
    from secaudit.report_state import publication,read_report
    from secaudit.security import PolicyError
    root=Path('/work/reports')
    run={'id':'a'*32,'mode':'offline','status':'COMPLETED_WITH_LIMITATIONS',
         'findings':[],'coverage':[],'assets':[],'components':[],'events':[]}
    reports(root,run);original=(root/'run.json').read_bytes()
    filler=Path('/work/filler')
    with filler.open('wb',buffering=0) as stream:
        try:
            while True:stream.write(b'x'*16384)
        except OSError as error:
            assert error.errno==errno.ENOSPC
        # Leave enough for the INCOMPLETE marker, but not the new 256 KiB report.
        stream.truncate(max(0,stream.tell()-65536))
    oversized=dict(run,events=['owned storage fixture '*13000])
    try:reports(root,oversized)
    except OSError as error:assert error.errno==errno.ENOSPC
    else:raise AssertionError('storage fixture did not exhaust bounded volume')
    assert (root/'run.json').read_bytes()==original
    assert publication(root)['status']=='INCOMPLETE'
    try:read_report(root,'technical.html')
    except PolicyError:pass
    else:raise AssertionError('incomplete report was downloadable')
    filler.unlink();reports(root,run)
    assert publication(root)['status']=='READY'
    assert json.loads(read_report(root,'run.json'))['findings']==[]
    print(json.dumps({'status':'PASS','volume_bytes':1048576,'checks':[
        'kernel ENOSPC on isolated tmpfs','old evidence bytes preserved',
        'incomplete download refused','export recovers after space reclaimed'],
        'pdf_generated':(root/'technical.pdf').is_file(),
        'limits':'Owned synthetic report fixture; not power-loss or physical-disk durability evidence'}))


def main():
    from secaudit.adapters import bounded,sandbox_command
    executable=str(Path(sys._base_executable).resolve())
    command=sandbox_command(executable,ROOT,extra=[(sys.base_prefix,sys.base_prefix)])
    # Preserve the runtime layout for libpython's executable-relative lookup.
    command[-1]=executable
    command[-2:-2]=['--size','1048576','--tmpfs','/work']
    command+=['-B','/input/integration/storage_acceptance.py','--inside']
    # The same supported Python runtime is read-only.
    # Only owned fixture diagnostics are captured; no user assessments are loaded.
    code,out=bounded(['/bin/sh','-c',shlex.join(command)+' 2>&1'],30,1_000_000)
    if code:
        print('::error::Isolated storage fixture failed: '+out.decode(errors='replace')[-2000:].replace('\n','%0A'))
        raise ValueError('Isolated full-storage acceptance failed; no sandbox fallback')
    result=json.loads(out)
    result['source_commit']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    path=ROOT/'artifacts/checkpoints/independent/storage.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':
    if '--inside' in sys.argv:exercise()
    else:main()
