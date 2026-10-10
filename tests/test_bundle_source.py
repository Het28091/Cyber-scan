import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secaudit import bundle
from secaudit.security import PolicyError


class BundleSourceTests(unittest.TestCase):
    def test_direct_prepare_refuses_private_or_changed_inputs_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            def git(*args):return subprocess.check_output(['git',*args],cwd=root,stderr=subprocess.DEVNULL,text=True).strip()
            git('init');(root/'README.md').write_text('owned fixture')
            git('add','README.md');git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture')
            (root/'scripts').mkdir();private=root/'scripts/private.env'
            with patch.object(bundle,'__file__',str(root/'secaudit/bundle.py')):
                private.write_text('synthetic-private-canary')
                with self.assertRaisesRegex(PolicyError,'untracked'):bundle.prepare(root/'output')
                self.assertFalse((root/'output').exists())
                (root/'.gitignore').write_text('*.env\n')
                with self.assertRaisesRegex(PolicyError,'ignored'):bundle.prepare(root/'output')
                self.assertFalse((root/'output').exists())
                private.unlink();(root/'README.md').write_text('changed source')
                with self.assertRaisesRegex(PolicyError,'uncommitted'):bundle.prepare(root/'output')
                self.assertFalse((root/'output').exists())

    def test_no_git_checkout_is_not_a_package_source(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PolicyError):bundle.verify_source(temp)
