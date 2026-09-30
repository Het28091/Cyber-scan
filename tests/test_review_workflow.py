import copy
import json
from pathlib import Path
import tempfile
import unittest
from secaudit.models import Finding
from secaudit.review import Reviews,compare,load_run,with_reviews
from secaudit.security import PolicyError


class ReviewWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.finding=Finding('PY-SHELL','Shell call','app.py','shell=True','Use argument list',line=1).to_dict()
        self.before={'id':'a'*32,'status':'COMPLETED_WITH_LIMITATIONS','findings':[self.finding],
                     'started':'2026-09-29T10:00:00+00:00','finished':'2026-09-29T10:01:00+00:00',
                     'assessment_context':{'version':1,'source_root':'owned'},'coverage':[{'module':'source','status':'PARTIAL','reason':'Bounded source checks'}]}
        self.after=dict(copy.deepcopy(self.before),id='b'*32,findings=[],started='2026-09-29T10:02:00+00:00',finished='2026-09-29T10:03:00+00:00')
        self.save(self.before);self.save(self.after)
        self.store=Reviews(self.root);self.addCleanup(self.store.close)

    def save(self,run):
        folder=self.root/run['id'];folder.mkdir(exist_ok=True);(folder/'run.json').write_text(json.dumps(run),encoding='utf-8')

    def update(self,**values):
        data={'status':'CONFIRMED','note':'Manually reviewed call site','evidence':'app.py:1','revision':0};data.update(values)
        return self.store.update(self.before['id'],self.finding['id'],data)

    def test_persistence_history_and_original_evidence_unchanged(self):
        original=(self.root/self.before['id']/'run.json').read_bytes()
        self.update(owner='maintainer');self.update(status='REMEDIATION_PENDING',revision=1,note='Fix scheduled')
        second=Reviews(self.root)
        try:snapshot=second.snapshot(self.before['id'])
        finally:second.close()
        self.assertEqual(len(snapshot['history']),2)
        self.assertEqual(snapshot['decisions'][self.finding['id']]['revision'],2)
        self.assertEqual((self.root/self.before['id']/'run.json').read_bytes(),original)
        self.assertEqual(with_reviews(self.root,self.before)['operator_review']['history'],snapshot['history'])

    def test_stale_revision_does_not_overwrite_or_append(self):
        self.update()
        with self.assertRaisesRegex(PolicyError,'reload'):self.update(status='FALSE_POSITIVE')
        self.assertEqual(len(self.store.snapshot(self.before['id'])['history']),1)

    def test_resolution_requires_operator_evidence_and_eligible_retest(self):
        for fields in ({'evidence':''},{'retest_run':''},{'retest_run':self.before['id']}):
            data={'status':'RESOLVED','retest_run':self.after['id']};data.update(fields)
            with self.subTest(fields=fields),self.assertRaises(PolicyError):self.update(**data)
        decision=self.update(status='RESOLVED',retest_run=self.after['id'],note='Verified revised code and repeated authorized test')
        self.assertEqual(decision['status'],'RESOLVED')
        # Reopening preserves the prior resolution in history.
        self.update(status='OPEN',revision=1,note='Additional review requested')
        self.assertEqual(len(self.store.snapshot(self.before['id'])['history']),2)

    def test_missing_findings_do_not_resolve_automatically(self):
        result=compare(self.before,self.after)
        self.assertEqual(result['rows'][0]['status'],'NOT_OBSERVED')
        self.assertEqual(self.store.snapshot(self.before['id'])['decisions'],{})
        for changes in ({'status':'FAILED'},{'assessment_context':{}},{'started':'2026-09-29T09:00:00+00:00'},{'started':'invalid'},{'coverage':[{'module':'source','status':'NOT TESTED'}]},
                        {'coverage':[{'module':'target_workflow','status':'PARTIAL','execution_complete':False}]}):
            current=dict(self.after,**changes);self.save(current)
            self.assertEqual(compare(self.before,current)['rows'][0]['status'],'NOT_RETESTED')
            with self.assertRaises(PolicyError):self.update(status='RESOLVED',retest_run=current['id'])

    def test_repeated_and_moved_findings_cannot_be_resolved(self):
        for line,expected in ((1,'OBSERVED_AGAIN'),(2,'POSSIBLY_MOVED')):
            f=Finding('PY-SHELL','Shell call','app.py','shell=True','Use argument list',line=line).to_dict()
            current=dict(self.after,findings=[f]);self.save(current)
            self.assertEqual(compare(self.before,current)['rows'][0]['status'],expected)
            with self.assertRaises(PolicyError):self.update(status='RESOLVED',retest_run=current['id'])

    def test_bounded_input_and_redaction(self):
        for fields in ({'note':''},{'note':'x'*4001},{'owner':5},{'revision':True},{'status':'AUTO_CONFIRMED'},{'command':'run me'}):
            with self.subTest(fields=fields),self.assertRaises(PolicyError):self.update(**fields)
        saved=self.update(note='password="synthetic-secret-value"')
        self.assertNotIn('synthetic-secret-value',json.dumps(saved))
        self.assertNotIn(b'synthetic-secret-value',(self.root/'reviews.sqlite3').read_bytes())

    def test_rejects_unknown_and_nonterminal_evidence(self):
        for ident in ('../escape','c'*32):
            with self.assertRaises(PolicyError):load_run(self.root,ident)
        with self.assertRaises(PolicyError):self.store.update(self.before['id'],'c'*32,{'revision':0})
        self.save(dict(self.before,status='RUNNING'))
        with self.assertRaises(PolicyError):self.update()

    def test_real_cli_review_and_comparison(self):
        import subprocess,sys
        decision=self.root/'decision.json';decision.write_text(json.dumps({'status':'CONFIRMED','note':'Reviewed source','evidence':'app.py:1','revision':0}))
        command=[sys.executable,'-m','secaudit']
        result=subprocess.run(command+['review',self.before['id'],self.finding['id'],'--output',str(self.root),'--decision',str(decision)],capture_output=True,text=True,timeout=15,cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['revision'],1)
        result=subprocess.run(command+['compare',self.before['id'],self.after['id'],'--output',str(self.root)],capture_output=True,text=True,timeout=15,cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['rows'][0]['status'],'NOT_OBSERVED')

    def test_pdf_export_with_operator_review(self):
        from secaudit.pdf_report import pdf_reports
        self.update(note='Reviewed <untrusted> text & source safely.')
        run=with_reviews(self.root,dict(self.before,mode='offline',events=[],limitations=[]))
        pdf_reports(self.root,run)
        for name in ('technical.pdf','executive.pdf'):
            self.assertTrue((self.root/name).read_bytes().startswith(b'%PDF-'))


if __name__=='__main__':unittest.main()
