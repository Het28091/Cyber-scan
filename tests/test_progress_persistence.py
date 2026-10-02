import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform=='linux','CLI isolation requires Linux')
class ProgressPersistenceTests(unittest.TestCase):
    def test_terminal_failure_preserves_progress_since_last_disk_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';source.mkdir()
            for name in ('a.py','b.py','c.py'):(source/name).write_text('value = 1\n')
            config=root/'config.json'
            config.write_text(json.dumps({'source':str(source),'output':str(root/'runs'),
                'modules':['source'],'max_files':2}))
            script='''
import sys
from unittest.mock import patch
from secaudit.cli import main
with patch('secaudit.cli.time.monotonic',return_value=1000):
    raise SystemExit(main(['scan','--config',sys.argv[1]]))
'''
            process=subprocess.run([sys.executable,'-c',script,str(config)],capture_output=True,text=True,timeout=20)
            self.assertEqual(process.returncode,1,process.stderr)
            summary=json.loads(process.stdout);folder=Path(summary['reports'])
            partial=json.loads((folder/'partial.json').read_text());terminal=json.loads((folder/'run.json').read_text())
            self.assertEqual(len(partial['assets']),1)
            self.assertEqual([a['asset'] for a in terminal['assets']],['a.py','b.py'])
            self.assertEqual(terminal['status'],'FAILED')
