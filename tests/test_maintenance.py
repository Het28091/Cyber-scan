import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from secaudit.maintenance import backup,restore,inventory
from secaudit.profiles import Profiles
from secaudit.review import Reviews
from secaudit.store import Store
from secaudit.security import PolicyError


class SchemaTests(unittest.TestCase):
    def test_future_schemas_fail_before_modification(self):
        for name,kind in [('profiles.sqlite3',Profiles),('reviews.sqlite3',Reviews),('runs.sqlite3',Store)]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/name;db=sqlite3.connect(path);db.execute('PRAGMA user_version=2');db.close()
                before=path.read_bytes()
                with self.assertRaisesRegex(PolicyError,'newer'):kind(temp)
                self.assertEqual(path.read_bytes(),before)


@unittest.skipUnless(sys.platform=='linux','quiescent backup lock requires Linux fcntl')
class MaintenanceTests(unittest.TestCase):
    def fixture(self,root):
        root.mkdir();store=Store(root)
        run={'id':'a'*32,'status':'COMPLETED_WITH_LIMITATIONS','findings':[],'events':[]}
        store.save(run);store.db.close();(root/run['id']).mkdir()
        (root/run['id']/'run.json').write_text(json.dumps(run))
        profiles=Profiles(root)
        try:profiles.save({'name':'owned fixture','configuration':{'source':'demo/source','preset':'offline'}})
        finally:profiles.close()
        reviews=Reviews(root);reviews.close()

    def test_round_trip_preserves_all_bytes_and_reopens_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'runs';self.fixture(source)
            original=inventory(source);backup(source,root/'backup');restore(root/'backup',root/'restored')
            self.assertEqual(inventory(root/'restored'),original)
            self.assertEqual(inventory(source),original)
            profiles=Profiles(root/'restored')
            try:self.assertEqual(profiles.list()[0]['name'],'owned fixture')
            finally:profiles.close()
            store=Store(root/'restored')
            try:self.assertEqual(store.get('a'*32)['status'],'COMPLETED_WITH_LIMITATIONS')
            finally:store.db.close()
            with self.assertRaises(PolicyError):restore(root/'backup',source)

    def test_active_lock_symlinks_and_tampering_are_rejected(self):
        from secaudit.jobs import Jobs
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'runs';self.fixture(source);jobs=Jobs(source)
            try:
                with self.assertRaisesRegex(PolicyError,'stop the dashboard'):backup(source,root/'copy')
            finally:jobs.close()
            (source/'linked').symlink_to(source/'runs.sqlite3')
            with self.assertRaisesRegex(PolicyError,'symbolic'):backup(source,root/'copy')
            (source/'linked').unlink();backup(source,root/'copy')
            (root/'copy'/'extra').write_text('tampered')
            with self.assertRaisesRegex(PolicyError,'integrity'):restore(root/'copy',root/'restored')
            self.assertFalse((root/'restored').exists())

    def test_incomplete_reports_and_live_cli_state_block_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'runs';self.fixture(source)
            marker=source/('a'*32)/'report-publication.json'
            marker.write_text(json.dumps({'schema':1,'status':'INCOMPLETE'}))
            with self.assertRaisesRegex(PolicyError,'incomplete'):backup(source,root/'copy')
            marker.unlink();store=Store(source)
            run=store.get('a'*32);run['status']='RUNNING';store.save(run);store.db.close()
            with self.assertRaisesRegex(PolicyError,'CLI'):backup(source,root/'copy')

    def test_manifest_path_injection_never_writes_outside_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'runs';self.fixture(source);backup(source,root/'copy')
            path=root/'copy'/'backup-manifest.json';data=json.loads(path.read_text())
            data['files']['../escape']={'bytes':0,'sha256':'0'*64};path.write_text(json.dumps(data))
            with self.assertRaisesRegex(PolicyError,'integrity'):restore(root/'copy',root/'restored')
            self.assertFalse((root/'escape').exists())
