"""Trusted launcher: verify kernel cgroup limits before executing the outer sandbox.

Executed as a file by a transient user service; no application environment needed.
"""
import os
from pathlib import Path
import resource
import sys

MEMORY=1024**3
TASKS=128
ADDRESS=2*1024**4


def verify():
    mounts=Path('/proc/self/mountinfo').read_text().splitlines()
    if not any(line.split()[4]=='/sys/fs/cgroup' and line.split(' - ')[1].split()[0]=='cgroup2' for line in mounts):
        raise ValueError('cgroup v2 is required')
    membership=next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    root=Path('/sys/fs/cgroup');group=(root/membership.lstrip('/')).resolve()
    if group==root or not group.is_relative_to(root):raise ValueError('dedicated cgroup is required')
    memory=int((group/'memory.max').read_text());tasks=int((group/'pids.max').read_text())
    swap=int((group/'memory.swap.max').read_text())
    if not 0<memory<=MEMORY or not 0<tasks<=TASKS or swap!=0:raise ValueError('kernel resource budgets are not enforced')
    for kind,maximum in ((resource.RLIMIT_AS,ADDRESS),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_FSIZE,1_000_000)):
        soft,hard=resource.getrlimit(kind)
        if soft<=0 or hard<=0 or soft>maximum or hard>maximum:raise ValueError('process resource budgets are not enforced')
    return {'memory_max':memory,'swap_max':swap,'tasks_max':tasks,'address_max':ADDRESS}


if __name__=='__main__':
    try:
        verify()
        if len(sys.argv)<2:raise ValueError('sandbox command required')
        os.execv(sys.argv[1],sys.argv[1:])
    except (ValueError,OSError,StopIteration):
        print('Renderer resource containment unavailable; execution refused.',file=sys.stderr)
        raise SystemExit(2)
