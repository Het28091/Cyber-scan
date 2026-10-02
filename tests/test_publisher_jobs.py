import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('publisher_jobs',Path(__file__).resolve().parents[1]/'scripts/publish-release.py')
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)


class PublisherJobsTests(unittest.TestCase):
    def test_missing_or_failed_containment_cannot_publish(self):
        names={'test','live-acceptance','browser-acceptance','target-browser-acceptance','operations-acceptance','semgrep-acceptance'}
        names|={f'distribution-acceptance ({os}, {version})' for os in ('ubuntu-22.04','ubuntu-24.04') for version in ('3.11','3.12','3.13','3.14')}
        names|={f'inventory-acceptance ({name})' for name in ('syft','trivy')}
        run={'head_sha':'a'*40,'status':'completed','conclusion':'success','event':'push','path':'.github/workflows/test.yml','head_repository':{'full_name':'owned/repo'},'run_attempt':1}
        jobs=[{'name':name,'status':'completed','conclusion':'success'} for name in names]
        with patch.object(publisher,'github',side_effect=[run,{'jobs':jobs}]):
            self.assertIn('target-browser-acceptance',publisher.verify_ci('owned/repo',1,'a'*40)['required_jobs'])
        for value in ('failure','skipped'):
            bad=[dict(j,conclusion=value) if j['name']=='target-browser-acceptance' else j for j in jobs]
            with self.subTest(value=value),patch.object(publisher,'github',side_effect=[run,{'jobs':bad}]),self.assertRaisesRegex(ValueError,'target-browser'):
                publisher.verify_ci('owned/repo',1,'a'*40)
