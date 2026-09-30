"""Render a pinned HTML snapshot in an offline, isolated Chromium process.

This deliberately does not execute application JavaScript or submit forms.
"""
import shutil
import tempfile
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
        command=sandbox_command(exe,folder)+['--headless','--disable-gpu','--disable-background-networking','--disable-extensions','--no-first-run','--blink-settings=scriptEnabled=false','--user-data-dir=/tmp/profile','--dump-dom','file:///input/page.html']
        # Chromium's own sandbox stays enabled. A host that cannot nest the
        # sandboxes is unsupported; do not fall back to --no-sandbox.
        code,dom=bounded(command,timeout,1_000_000,max_address_bytes=8*1024**3)
        if code or b'<html' not in dom.lower(): raise PolicyError('browser snapshot renderer unavailable')
        parser=Inventory();parser.feed(dom.decode('utf-8','replace'))
        return {'forms':parser.forms,'password_inputs':parser.passwords,'links':parser.links,
                'javascript':False,'browser_network':False,'renderer':'Chromium offline snapshot'}
