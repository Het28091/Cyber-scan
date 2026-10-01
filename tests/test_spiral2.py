"""Regression coverage for first-round profile, module and report integration."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from secaudit.config import load
from secaudit.dashboard_config import assessment_options
from secaudit.models import Finding
from secaudit.profiles import Profiles,preview,validate_configuration
from secaudit.review import Reviews
from secaudit.security import PolicyError

ROOT=Path(__file__).resolve().parents[1]


class ProfileIntegrationTests(unittest.TestCase):
    def test_preview_uses_actual_preset_defaults(self):
        for preset in ('offline','internet'):
            with self.subTest(preset=preset):
                expected=load(ROOT/'config'/(preset+'.json'))
                config=validate_configuration({'source':'demo/source','preset':preset})
                self.assertEqual(config['modules'],expected.modules)
                self.assertEqual(preview(config)['summary']['selected_source_modules'],expected.modules)

    def test_profiles_reopen_revisions_and_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            store=Profiles(temp)
            try:
                saved=store.save({'name':'Offline source','configuration':{'source':'demo/source','preset':'offline','modules':['source'],'assessment_options':{'max_files':7}}})
                changed=store.save({'id':saved['id'],'revision':1,'name':'Changed','configuration':saved['configuration']})
                with self.assertRaises(PolicyError):store.save({'id':saved['id'],'revision':1,'name':'Stale','configuration':saved['configuration']})
                with self.assertRaises(PolicyError):store.delete(saved['id'],1)
            finally:store.close()
            store=Profiles(temp)
            try:
                self.assertEqual(store.list(),[changed]);self.assertEqual(changed['configuration']['assessment_options']['max_files'],7)
                store.delete(saved['id'],2);self.assertEqual(store.list(),[])
            finally:store.close()

    def test_profile_rejects_consent_upload_and_invalid_modules(self):
        base={'source':'demo/source','preset':'offline'}
        for extra in ({'archive_base64':'UEs='},{'ai_disclosure_accepted':True},{'modules':['source','source']},{'modules':['shell']},{'modules':['online_dependencies']},{'assessment_options':{'max_files':True}},{'assessment_options':{'max_file_bytes':0}}):
            with self.subTest(extra=extra),self.assertRaises(PolicyError):validate_configuration(base|extra)

    def test_selection_disables_osv_without_disabling_public_target_mode(self):
        cfg=load(ROOT/'config/internet.json')
        assessment_options(cfg,{'modules':['source','openapi'],'assessment_options':{'max_files':9,'pdf_required':True}})
        self.assertEqual(cfg.mode,'internet');self.assertEqual(cfg.modules,['source','openapi']);self.assertEqual(cfg.max_files,9);self.assertTrue(cfg.pdf_required)
        self.assertNotIn('OSV package-identifier disclosure selected',preview({'source':'demo/source','preset':'internet','modules':['source']})['summary']['network_disclosure'])

    def test_target_only_configuration_and_no_network_during_preview(self):
        origin='http://127.0.0.1:3000'
        data={'preset':'offline','target':origin,'modules':[], 'scope':{'authorization':'Owned local fixture','environment':'lab','origins':[origin],'exclusions':[],'allowed_ips':['127.0.0.1'],'profiles':['passive'],'max_requests':2,'max_seconds':10}}
        with patch('socket.getaddrinfo',side_effect=AssertionError('preview must not resolve DNS')):
            self.assertEqual(preview(data)['summary']['selected_source_modules'],[])
        with self.assertRaises(PolicyError):validate_configuration({'source':'demo/source','preset':'offline','modules':[]})


class ReportExportTests(unittest.TestCase):
    def fixture(self,root):
        finding=Finding('PY-DYNAMIC-EXEC','Dynamic execution','app.py','Syntax candidate','Remove dynamic evaluation',line=1).to_dict()
        run={'id':'a'*32,'mode':'offline','status':'COMPLETED_WITH_LIMITATIONS','started':'2026-09-30T00:00:00+00:00','finished':'2026-09-30T00:01:00+00:00','findings':[finding],'assets':[],'components':[],'coverage':[{'module':'source','status':'PARTIAL','reason':'Heuristic'}],'events':[],'limitations':[],
             'ai_suggestions':{'suggestions':[{'id':finding['id'],'text':'Untrusted suggestion <script>alert(1)</script>'}]}}
        folder=root/run['id'];folder.mkdir();(folder/'run.json').write_text(json.dumps(run),encoding='utf-8')
        reviews=Reviews(root)
        try:reviews.update(run['id'],finding['id'],{'revision':0,'status':'REMEDIATION_PENDING','note':'Fix scheduled','owner':'maintainer','due_date':'2026-10-14'})
        finally:reviews.close()
        return run

    @unittest.skipUnless(sys.platform=='linux','atomic report export requires Linux fchmod')
    def test_terminal_export_preserves_findings_and_adds_current_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);run=self.fixture(root)
            process=subprocess.run([sys.executable,'-m','secaudit','export-reports',run['id'],'--output',str(root)],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(process.returncode,0,process.stderr)
            folder=root/run['id'];saved=json.loads((folder/'run.json').read_text())
            self.assertEqual(saved['findings'],run['findings']);self.assertTrue(saved['report_snapshot']['includes_operator_reviews'])
            self.assertIn('2026-10-14',(folder/'technical.md').read_text())
            html=(folder/'technical.html').read_text();self.assertIn('&lt;script&gt;',html);self.assertNotIn('<script>alert',html)
            self.assertTrue((folder/'technical.pdf').read_bytes().startswith(b'%PDF'))

    def test_export_rejects_running_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);run=self.fixture(root);run['status']='RUNNING';(root/run['id']/'run.json').write_text(json.dumps(run))
            process=subprocess.run([sys.executable,'-m','secaudit','export-reports',run['id'],'--output',str(root)],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(process.returncode,2);self.assertFalse((root/run['id']/'technical.pdf').exists())


@unittest.skipUnless(sys.platform=='linux','real job queue requires Linux fcntl and process isolation')
class QueueIntegrationTests(unittest.TestCase):
    fixture=ReportExportTests.fixture
    def wait(self,jobs,ident):
        until=time.monotonic()+30
        while time.monotonic()<until:
            result=jobs.detail(ident)
            if result['status'] not in ('QUEUED','RUNNING'):return result
            time.sleep(.05)
        self.fail('job did not finish')

    def test_report_queue_and_failed_preflight_persist(self):
        from secaudit.jobs import Jobs
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);run=self.fixture(root);jobs=Jobs(root)
            try:
                report=jobs.refresh_reports(run['id']);result=self.wait(jobs,report['id'])
                self.assertEqual(result['status'],'COMPLETED');self.assertEqual(result['run_id'],run['id'])
                self.assertEqual(result['diagnostic']['code'],'REPORTS_REFRESHED');self.assertNotIn('preflight',result)
                failed=jobs.submit({'preset':'offline','source':str(root/'absent'),'modules':['source']})
                result=self.wait(jobs,failed['id']);self.assertEqual(result['status'],'FAILED')
                self.assertFalse(result['preflight']['ready']);self.assertNotIn('preflight',next(j for j in jobs.list() if j['id']==failed['id']))
            finally:jobs.close()
            jobs=Jobs(root)
            try:self.assertFalse(jobs.detail(failed['id'])['preflight']['ready'])
            finally:jobs.close()
