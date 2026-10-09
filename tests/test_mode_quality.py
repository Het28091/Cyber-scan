"""Mode-specific regression cases; fixture accuracy is not real-provider acceptance."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secaudit.ai import Provider
from secaudit.config import Config,AIConfig
from secaudit.network import scan_web
from secaudit.scanners import source_scan
from secaudit.security import Scope,PolicyError


class OfflineQualityTests(unittest.TestCase):
    def test_final_docker_runtime_user(self):
        cases=[
            ('FROM base\nUSER app\nUSER root\n',True),
            ('FROM base AS build\nUSER app\nFROM other\n',True),
            ('FROM base\nUSER 0:1000\n',True),
            ('FROM base\nUSER 00\n',True),
            ('FROM base\nUSER ${APP_USER}\n',True),
            ('FROM base\n# USER app\n',True),
            ('FROM base\nUSER 1000:0\n',False),
            ('FROM base AS build\nUSER app\nFROM build\n',False),
            ('FROM base AS build\nUSER root\nFROM other\nUSER app\n',False),
            ('FROM base\nUSER \\\n app\n',False),
        ]
        with tempfile.TemporaryDirectory() as temp:
            for source,expected in cases:
                with self.subTest(source=source):
                    Path(temp,'Dockerfile').write_text(source)
                    findings,_,_,_=source_scan(temp,Config(modules=['config']),lambda *_:None)
                    self.assertEqual(any(f.rule=='DOCKER-USER' for f in findings),expected)


class WebQualityTests(unittest.TestCase):
    def test_empty_versus_nonempty_headers(self):
        url='https://127.0.0.1/page'
        scope=Scope(dict(authorization='owned header fixture',origins=[url],exclusions=[],
                         environment='test',profiles=['passive'],allowed_ips=['127.0.0.1'],max_requests=1,max_seconds=5))
        for values,expected in [(['',' ','\t'],3),(["default-src 'none'",'nosniff','max-age=86400'],0)]:
            headers=list(zip(['Content-Security-Policy','X-Content-Type-Options','Strict-Transport-Security'],values))
            with self.subTest(values=values),patch('secaudit.network.request',return_value=(200,headers,b'')),patch('secaudit.network.time.sleep'):
                fs,_,_=scan_web(url,scope,lambda *_:None)
                self.assertEqual(len(fs),expected)
                if fs:self.assertTrue(all('empty' in f.description.lower() for f in fs))


class OnlineAIQualityTests(unittest.TestCase):
    def test_interrupted_or_nontext_completions_are_not_accepted(self):
        cfg=Config(mode='connected-ai',ai=AIConfig(enabled=True,provider='openai-compatible',
            endpoint='https://owned.example.invalid/v1',model='fixture',approved_ips=['192.0.2.1']))
        content='{"suggestions":[{"id":"owned","text":"Review parameter binding"}]}'
        finding={'id':'owned','rule':'PY-SQL-DYNAMIC','severity':'HIGH'}
        with patch.dict('os.environ',{'SECAUDIT_EXPERIMENTAL_AI':'1'}):
            provider=Provider(cfg)
            for reason in ['length','content_filter','tool_calls','unexpected']:
                with self.subTest(reason=reason),patch.object(provider,'call',return_value={'choices':[{'finish_reason':reason,'message':{'content':content}}]}),self.assertRaises(PolicyError):
                    provider.suggest([finding])
            for extra in [{'refusal':'refused'},{'tool_calls':[{}]},{'function_call':{'name':'unexpected'}}]:
                with self.subTest(extra=extra),patch.object(provider,'call',return_value={'choices':[{'finish_reason':'stop','message':dict(content=content,**extra)}]}),self.assertRaises(PolicyError):
                    provider.suggest([finding])
            with patch.object(provider,'call',return_value={'choices':[{'finish_reason':'stop','message':{'content':content}}]}):
                self.assertEqual(provider.suggest([finding])['suggestions'][0]['id'],'owned')
