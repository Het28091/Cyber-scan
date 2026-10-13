import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from secaudit.dashboard_setup import website_scope, prepared_ai
from secaudit.security import PolicyError, Scope


class SetupTests(unittest.TestCase):
    def test_scope_draft_resolves_only_requested_host_without_http(self):
        rows=[(2,1,6,'',('192.0.2.2',443)),(2,1,6,'',('192.0.2.2',443))]
        with patch('secaudit.dashboard_setup.socket.getaddrinfo',return_value=rows) as dns, \
             patch('secaudit.network.request',side_effect=AssertionError('HTTP forbidden')):
            result=website_scope({'target':'https://owned.example.invalid/app','authorization':'Owner approval'})
        self.assertEqual(result['scope']['origins'],['https://owned.example.invalid/app'])
        self.assertEqual(result['scope']['allowed_ips'],['192.0.2.2'])
        self.assertEqual(dns.call_args.args,('owned.example.invalid',443))
        with patch('secaudit.security.socket.getaddrinfo',return_value=[(2,1,6,'',('192.0.2.3',443))]):
            with self.assertRaises(PolicyError):
                Scope(result['scope']).check('https://owned.example.invalid/app')

    def test_scope_invalid_inputs_do_not_resolve(self):
        cases=[{'target':'https://user:secret@owned.invalid/','authorization':'Owner'},
               {'target':'https://owned.invalid/?token=secret','authorization':'Owner'},
               {'target':'https://owned.invalid/','authorization':''},
               {'target':'https://owned.invalid/','authorization':'Owner','extra':True}]
        with patch('secaudit.dashboard_setup.socket.getaddrinfo',side_effect=AssertionError('DNS forbidden')):
            for case in cases:
                with self.subTest(case=case),self.assertRaises(PolicyError):website_scope(case)

    def settings(self):
        return {'mode':'connected-ai','ai':{'enabled':True,'provider':'openai-compatible',
            'endpoint':'https://provider.example.invalid/v1','model':'configured-model',
            'approved_ips':['192.0.2.1'],'api_key_env':'SECAUDIT_FIXTURE_KEY',
            'failure_policy':'required','response_format':'json_object','output_tokens':1024}}

    def test_prepared_api_preserves_settings_and_never_returns_credential(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'ai.json';path.write_text(json.dumps(self.settings()))
            env={'SECAUDIT_EXPERIMENTAL_AI':'1','SECAUDIT_AI_CONFIG':str(path),'SECAUDIT_FIXTURE_KEY':'PRIVATE_CREDENTIAL_VALUE'}
            with patch.dict(os.environ,env),patch('secaudit.ai.Provider.call',side_effect=AssertionError('Provider call forbidden')):
                result=prepared_ai({})
            self.assertTrue(result['credential_present'])
            self.assertEqual(result['ai']['response_format'],'json_object')
            self.assertEqual(result['ai']['output_tokens'],1024)
            self.assertNotIn('PRIVATE_CREDENTIAL_VALUE',json.dumps(result))

    def test_missing_key_and_local_runtime_are_not_claimed_ready(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'ai.json';data=self.settings();path.write_text(json.dumps(data))
            with patch.dict(os.environ,{'SECAUDIT_EXPERIMENTAL_AI':'1','SECAUDIT_AI_CONFIG':str(path)},clear=True):
                self.assertEqual(prepared_ai({})['status'],'CREDENTIAL_MISSING')
                data['mode']='local-ai';data['ai'].update(provider='ollama',endpoint='http://127.0.0.1:11434',approved_ips=['127.0.0.1'])
                path.write_text(json.dumps(data))
                result=prepared_ai({})
                self.assertIsNone(result['credential_present'])
                self.assertEqual(result['status'],'CONFIGURED_NOT_TESTED')

    def test_opt_in_required_and_browser_cannot_choose_file(self):
        with patch.dict(os.environ,{},clear=True),self.assertRaises(PolicyError):prepared_ai({})
        with self.assertRaises(PolicyError):prepared_ai({'path':'/etc/passwd'})

    def test_rejects_secret_fields_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'ai.json'
            with patch.dict(os.environ,{'SECAUDIT_EXPERIMENTAL_AI':'1','SECAUDIT_AI_CONFIG':str(path)}):
                data=self.settings();data['ai']['api_key']='PRIVATE';path.write_text(json.dumps(data))
                with self.assertRaises(PolicyError):prepared_ai({})
                path.write_text(' '*65537)
                with self.assertRaises(PolicyError):prepared_ai({})
                path.unlink();path.symlink_to(Path(temp)/'missing')
                with self.assertRaises(PolicyError):prepared_ai({})
