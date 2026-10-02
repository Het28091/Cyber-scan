import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from secaudit.reporting import reports
from secaudit.report_state import publication,read_report
from secaudit.security import PolicyError


@unittest.skipUnless(sys.platform=='linux','report publication uses Linux atomic permissions')
class PublicationTests(unittest.TestCase):
    def run_data(self):
        return {'id':'a'*32,'mode':'offline','status':'COMPLETED_WITH_LIMITATIONS',
            'findings':[],'coverage':[],'assets':[],'components':[],'events':[]}

    def test_failed_generation_preserves_evidence_and_blocks_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);reports(root,self.run_data());original=(root/'run.json').read_bytes()
            with patch('secaudit.reporting._write_reports',side_effect=OSError('disk full')):
                with self.assertRaises(OSError):reports(root,self.run_data())
            self.assertEqual((root/'run.json').read_bytes(),original)
            self.assertEqual(publication(root)['status'],'INCOMPLETE')
            with self.assertRaisesRegex(PolicyError,'incomplete'):read_report(root,'technical.html')
            reports(root,self.run_data());self.assertEqual(publication(root)['status'],'READY')
            self.assertEqual(json.loads(read_report(root,'run.json'))['findings'],[])

    def test_tampering_and_interrupted_publication_fail_closed(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);reports(root,self.run_data())
            (root/'technical.html').write_text('changed')
            with self.assertRaisesRegex(PolicyError,'integrity'):read_report(root,'technical.html')
            replace=os.replace
            def fail(source,destination):
                if Path(destination).name=='technical.html':raise OSError('publication interrupted')
                return replace(source,destination)
            with patch('secaudit.reporting.os.replace',side_effect=fail),self.assertRaises(OSError):reports(root,self.run_data())
            with self.assertRaisesRegex(PolicyError,'incomplete'):read_report(root,'findings.json')

    def test_legacy_reports_remain_readable(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'technical.html').write_bytes(b'legacy')
            self.assertEqual(read_report(root,'technical.html'),b'legacy')
