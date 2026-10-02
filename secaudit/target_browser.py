"""Render a pinned HTML snapshot in an offline, isolated Chromium process.

This deliberately does not execute application JavaScript or submit forms.
"""
import shutil
import tempfile
import subprocess
import uuid
from html.parser import HTMLParser
from pathlib import Path
from .security import PolicyError


class Inventory(HTMLParser):
    def __init__(self):
        super().__init__();self.forms=0;self.passwords=0;self.links=0

    def handle_starttag(self,tag,attrs):
        if tag=='form':self.forms+=1
        if tag=='a':self.links+=1
        if tag=='input' and dict(attrs).get('type','').lower()=='password':self.passwords+=1


def render(body,executable='',timeout=15):
    from .adapters import sandbox_command,bounded
    exe=executable or shutil.which('chromium') or shutil.which('chromium-browser')
    if not exe: raise PolicyError('REQUIRED_MISSING: explicitly install Chromium for target snapshots')
    if len(body)>65536: raise PolicyError('browser snapshot exceeds size limit')
    with tempfile.TemporaryDirectory(prefix='secaudit-browser-') as folder:
        path=Path(folder)/'page.html';path.write_bytes(body);path.chmod(0o600)
        helper=Path(__file__).with_name('browser_snapshot.py')
        command=sandbox_command(exe,folder,extra=[(str(helper),'/snapshot.py')])
        contained_exe=command.pop()
        command+=['/usr/bin/python3','/snapshot.py',contained_exe]
        # Chromium's own sandbox stays enabled. A host that cannot nest the
        # sandboxes is unsupported; do not fall back to --no-sandbox.
        # Modern Chromium reserves tens of GiB of PROT_NONE virtual space. Keep
        # a finite address cap, but enforce actual memory and all descendants in
        # a kernel cgroup instead of mistaking address reservation for resident RAM.
        manager=shutil.which('systemd-run');control=shutil.which('systemctl')
        if not manager or not control:raise PolicyError('REQUIRED_MISSING: user systemd/cgroup v2 renderer containment required')
        unit='secaudit-browser-'+uuid.uuid4().hex
        from .browser_resource import MEMORY,TASKS,service_command
        wrapper=service_command(command,timeout,unit)
        try:code,dom=bounded(wrapper,timeout+3,1_000_000)
        finally:
            # Explicitly stop the unit even if the client was cancelled. The
            # independent RuntimeMaxSec also bounds it if the parent is killed.
            try:subprocess.run([control,'--user','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
            except (OSError,subprocess.TimeoutExpired):pass
        if code or b'<html' not in dom.lower(): raise PolicyError('browser snapshot renderer unavailable')
        parser=Inventory();parser.feed(dom.decode('utf-8','replace'))
        return {'forms':parser.forms,'password_inputs':parser.passwords,'links':parser.links,
                'javascript':False,'browser_network':False,'renderer':'Chromium offline snapshot',
                'memory_limit_bytes':MEMORY,'swap_limit_bytes':0,'process_limit':TASKS,
                'containment':'verified cgroup v2 + Bubblewrap + Chromium sandbox'}
