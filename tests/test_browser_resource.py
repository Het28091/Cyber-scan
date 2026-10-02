from pathlib import Path
import sys
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform=='linux','kernel resource verification requires Linux')
class RendererResourceTests(unittest.TestCase):
    def check(self,**overrides):
        from secaudit.browser_resource import verify,ADDRESS,FILE_BYTES
        values={'/proc/self/mountinfo':'1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw',
            '/proc/self/cgroup':'0::/owned-fixture',
            '/sys/fs/cgroup/owned-fixture/memory.max':str(1024**3),
            '/sys/fs/cgroup/owned-fixture/memory.swap.max':'0',
            '/sys/fs/cgroup/owned-fixture/pids.max':'128'}
        values.update(overrides)
        import resource
        limits={resource.RLIMIT_AS:(ADDRESS,ADDRESS),resource.RLIMIT_NOFILE:(512,512),resource.RLIMIT_FSIZE:(FILE_BYTES,FILE_BYTES)}
        with patch.object(Path,'read_text',lambda path:values[str(path)]),patch('resource.getrlimit',side_effect=lambda kind:limits[kind]):return verify()

    def test_verified_limits_and_refused_unlimited_or_oversized_controls(self):
        self.assertEqual(self.check()['swap_max'],0)
        for key,value in [('memory.max','max'),('memory.max',str(2*1024**3)),('memory.swap.max','1'),('pids.max','max'),('pids.max','129')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                self.check(**{'/sys/fs/cgroup/owned-fixture/'+key:value})
        with self.assertRaises(ValueError):self.check(**{'/proc/self/cgroup':'0::/'})
