import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from secaudit.bundle import prepare_wheels
from secaudit.security import PolicyError


class WheelhouseTests(unittest.TestCase):
    def fixture(self,root):
        source=root/'local wheels';source.mkdir()
        wheel=source/'secaudit_fixture_pdf-1.0-py3-none-any.whl'
        with zipfile.ZipFile(wheel,'w') as z:
            folder='secaudit_fixture_pdf-1.0.dist-info/'
            z.writestr(folder+'METADATA','Metadata-Version: 2.1\nName: secaudit-fixture-pdf\nVersion: 1.0\n')
            z.writestr(folder+'WHEEL','Wheel-Version: 1.0\nGenerator: owned-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
            z.writestr(folder+'RECORD','')
        lock=root/'requirements.lock'
        lock.write_text('secaudit-fixture-pdf==1.0 --hash=sha256:'+hashlib.sha256(wheel.read_bytes()).hexdigest()+'\n')
        return source,wheel,lock

    def test_real_pip_local_resolution_ignores_inherited_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source,wheel,lock=self.fixture(root)
            with patch.dict(os.environ,{'PIP_INDEX_URL':'https://must-not-contact.invalid/simple','PIP_REQUIRE_VIRTUALENV':'true'}):
                prepare_wheels(root/'output',lock,source)
            self.assertEqual((root/'output'/wheel.name).read_bytes(),wheel.read_bytes())

    def test_modified_wheel_fails_locked_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source,wheel,lock=self.fixture(root)
            with wheel.open('ab') as f:f.write(b'changed')
            with self.assertRaises(PolicyError):prepare_wheels(root/'output',lock,source)

    def test_empty_wheelhouse_does_not_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source,wheel,lock=self.fixture(root);wheel.unlink()
            with self.assertRaises(PolicyError):prepare_wheels(root/'output',lock,source)

    def test_remote_or_missing_directory_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with self.assertRaises(PolicyError):prepare_wheels(root/'output',root/'lock','https://example.invalid/wheels')
            self.assertFalse((root/'output').exists())
