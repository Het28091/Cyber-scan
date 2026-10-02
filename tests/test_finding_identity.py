import unittest
from copy import deepcopy
from secaudit.models import Finding,dedup


class FindingIdentityTests(unittest.TestCase):
    def test_repeated_checkpoints_preserve_inputs_and_unique_provenance(self):
        first=Finding('RULE','Title','owned.py','Description','Fix',evidence=['first'])
        second=Finding('RULE','Title','owned.py','Description','Fix',scanner='other',evidence=['second'])
        inputs=[first,second,second];before=deepcopy(inputs)
        merged=dedup(inputs)
        self.assertEqual(inputs,before)
        self.assertEqual(merged,dedup(inputs))
        self.assertEqual(len(merged[0].provenance),1)
        self.assertEqual(merged[0].evidence,['first','second'])
        self.assertEqual(dedup(merged+merged),merged)
        merged[0].evidence.append('consumer edit')
        self.assertEqual(inputs,before)

    def test_identity_distinguishes_scope_and_is_stable_across_presentation(self):
        original=Finding('RULE','Title','owned.py','Description','Fix',line=3,role='reader')
        for field,value in [('rule','OTHER'),('asset','other.py'),('line',4),('role','writer'),('description','Other observation')]:
            changed=deepcopy(original);setattr(changed,field,value)
            with self.subTest(field=field):self.assertEqual(len(dedup([original,changed])),2)
        for field,value in [('title','New wording'),('remediation','Updated advice'),('timestamp','later'),('scanner','other')]:
            changed=deepcopy(original);setattr(changed,field,value)
            with self.subTest(field=field):self.assertEqual(changed.fingerprint,original.fingerprint)
