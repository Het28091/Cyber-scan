import json
import unittest
from unittest.mock import patch
from secaudit.ai import Provider
from secaudit.config import AIConfig,Config
from secaudit.security import PolicyError


class JsonModeTests(unittest.TestCase):
    def config(self,format='text'):
        return Config(mode='connected-ai',ai=AIConfig(enabled=True,provider='openai-compatible',
            endpoint='https://owned.example.invalid/v1',model='fixture',approved_ips=['192.0.2.1'],response_format=format))

    def test_json_mode_is_explicit_and_does_not_expand_disclosure(self):
        with patch.dict('os.environ',{'SECAUDIT_EXPERIMENTAL_AI':'1'}):
            for format in ('text','json_object'):
                provider=Provider(self.config(format))
                response={'choices':[{'message':{'content':'{"suggestions":[{"id":"owned","text":"Review"}]}'}}]}
                with patch.object(provider,'call',return_value=response) as call:
                    provider.suggest([{'id':'owned','rule':'PY-SHELL','severity':'HIGH','asset':'PRIVATE_PATH','description':'PRIVATE_TEXT'}])
                body=call.call_args.args[1]
                self.assertEqual(body.get('response_format'),{'type':'json_object'} if format=='json_object' else None)
                self.assertEqual(json.loads(body['messages'][1]['content']),[{'id':'owned','rule':'PY-SHELL','severity':'HIGH'}])

    def test_json_mode_does_not_trust_provider_schema(self):
        with patch.dict('os.environ',{'SECAUDIT_EXPERIMENTAL_AI':'1'}):
            provider=Provider(self.config('json_object'))
            for content in ('not json','{"suggestions":[{"id":"invented","text":"Confirmed"}]}','{"suggestions":[],"command":"execute"}'):
                response={'choices':[{'message':{'content':content}}]}
                with self.subTest(content=content),patch.object(provider,'call',return_value=response),self.assertRaises(PolicyError):
                    provider.suggest([{'id':'owned','rule':'PY-SHELL','severity':'HIGH'}])
            with self.assertRaisesRegex(PolicyError,'response format'):self.config('unrecognized').validate()
