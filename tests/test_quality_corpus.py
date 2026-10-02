import unittest
from integration.quality_corpus import evaluate


class QualityCorpusTests(unittest.TestCase):
    def test_declared_positive_and_clean_controls(self):
        result=evaluate()
        self.assertEqual(result['status'],'PASS',result['cases'])
        self.assertEqual(len(result['covered_builtin_rules']),21)
        self.assertEqual(result['clean_cases_passed'],11)
