"""Negative regressions for v0.6 acceptance; no real external services here."""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from secaudit.adapters import ADDRESS_LIMITS, parse, execute, probe, sandbox_command, runtime_mounts
from secaudit.config import Config
from secaudit.network import PinnedHTTP, request, scan_web
from secaudit.scanners import source_scan
from secaudit.security import PolicyError, Scope

ROOT=Path(__file__).resolve().parents[1]


class FailureTests(unittest.TestCase):
    def test_malformed_scanner_results_are_safe_errors(self):
        cases={'semgrep':[[],{}, {'results':[{}]}, {'results':[], 'errors':[{'message':'sensitive'}]}],
               'gitleaks':[{},[{}],[{'RuleID':'x','File':'a','StartLine':-1}]],
               'trivy':[[],{'Results':[{'Vulnerabilities':[{}]}]}], 'syft':[[],{'bomFormat':'wrong'}]}
        for name,values in cases.items():
            for value in values:
                with self.subTest(name=name,value=value),self.assertRaisesRegex(PolicyError,'raw content discarded'):
                    parse(name,json.dumps(value),'test')
        with self.assertRaises(PolicyError):parse('unknown','{}','test')

    def test_scanner_crash_never_returns_clean_result(self):
        for name in ('gitleaks','semgrep','trivy','syft'):
            with self.subTest(name=name),patch('secaudit.adapters.sandbox_command',return_value=['bwrap','--','isolated-tool']),patch('secaudit.adapters.probe',return_value=('/usr/bin/true','1.0.0')),patch('secaudit.adapters.bounded',return_value=(139,b'sensitive raw data')) as invocation:
                with self.assertRaisesRegex(PolicyError,'raw output discarded'):
                    execute(name,ROOT/'demo/source',{'rules':__file__,'cache':str(ROOT)},2)
                self.assertEqual(invocation.call_args.kwargs['max_address_bytes'],ADDRESS_LIMITS.get(name,2*1024**3))

    def test_sandbox_rejection_blocks_scanner_version_execution(self):
        with patch('shutil.which',return_value='/usr/bin/tool'),patch('secaudit.adapters.bounded',return_value=(1,b'no namespaces')) as run:
            with self.assertRaisesRegex(PolicyError,'POLICY_BLOCKED'):probe('gitleaks',{})
            self.assertEqual(run.call_count,1)
        with patch('shutil.which',return_value=None),self.assertRaises(PolicyError):sandbox_command('/bin/true')

    def test_semgrep_version_probe_disables_optional_network_features(self):
        with patch('secaudit.adapters.sandbox_command',return_value=['sandbox']),patch('secaudit.adapters.bounded',return_value=(0,b'1.175.0')) as run:
            probe('semgrep',{'executable':'/usr/bin/semgrep','rules':__file__})
            command=run.call_args_list[-1].args[0]
            self.assertIn('--disable-version-check',command)
            self.assertIn('--metrics=off',command)

    def test_semgrep_requires_a_narrow_public_trust_bundle_mount(self):
        with patch('secaudit.adapters.Path.is_file',return_value=False):
            with self.assertRaisesRegex(PolicyError,'CA certificate bundle'):
                runtime_mounts('semgrep')
        with patch('secaudit.adapters.Path.is_file',return_value=True):
            mounts=runtime_mounts('semgrep')
            self.assertEqual(len(mounts),1)
            self.assertEqual(mounts[0][1],'/etc/ssl/certs/ca-certificates.crt')
            with patch('shutil.which',return_value='/usr/bin/bwrap'):
                command=sandbox_command('/usr/bin/true',extra=mounts)
            self.assertIn('--unshare-all',command)
            self.assertIn('--clearenv',command)
            self.assertEqual(command[command.index(mounts[0][0])-1],'--ro-bind')
            self.assertNotIn('/etc',command)
        self.assertEqual(runtime_mounts('gitleaks'),[])

    def test_inventory_adapter_offline_controls(self):
        with patch('shutil.which',return_value='/usr/bin/bwrap'),patch('secaudit.adapters.probe',return_value=('/usr/local/bin/tool','test')),patch('secaudit.adapters.bounded') as run:
            run.return_value=(0,b'{"bomFormat":"CycloneDX","components":[]}')
            execute('syft',ROOT/'demo/source',{},2)
            command=run.call_args.args[0]
            self.assertIn('SYFT_CHECK_FOR_APP_UPDATE',command[:command.index('--')])
            self.assertNotIn('--check-for-app-update=false',command)
            run.return_value=(0,b'{"Results":[]}')
            execute('trivy',ROOT/'demo/source',{'cache':str(ROOT)},2)
            command=run.call_args.args[0]
            self.assertEqual(command[command.index('--cache-backend')+1],'memory')
            for flag in ('--disable-telemetry','--offline-scan','--skip-db-update','--skip-java-db-update'):
                self.assertIn(flag,command)
            self.assertNotIn('--scan-cache',command)

    def test_tls_and_socket_failure_closes_socket(self):
        for secure in (False,True):
            fake=MagicMock()
            if not secure:fake.connect.side_effect=TimeoutError()
            with patch('socket.socket',return_value=fake),patch('ssl.create_default_context') as tls:
                tls.return_value.wrap_socket.side_effect=OSError('bad certificate')
                with self.assertRaises(OSError):PinnedHTTP('test.example',443,'127.0.0.1',.01,secure).connect()
                fake.close.assert_called_once()

    def test_response_timeout_and_overflow_close_connection(self):
        scope=MagicMock();scope.check.return_value='127.0.0.1';scope.auth=None
        for failure in (TimeoutError(),http.client.IncompleteRead(b'x'),None):
            with patch('secaudit.network.PinnedHTTP') as cls:
                response=cls.return_value.getresponse.return_value
                response.read.side_effect=failure;response.read.return_value=b'xx'
                with self.assertRaises((OSError,http.client.HTTPException,PolicyError)):
                    request('http://127.0.0.1/',scope,max_bytes=1)
                cls.return_value.close.assert_called_once()

    def test_crawler_timeout_and_server_crash_preserve_failure_events(self):
        scope=Scope(dict(authorization='owned fixture',origins=['http://127.0.0.1/'],exclusions=[],environment='test',profiles=['passive'],max_requests=2,max_seconds=1,allowed_ips=['127.0.0.1']))
        with patch('secaudit.network.request',side_effect=TimeoutError()):
            findings,assets,events=scan_web('http://127.0.0.1/',scope,lambda *_:None)
            self.assertFalse(findings);self.assertFalse(assets);self.assertIn('TimeoutError',events[0])
        with patch('secaudit.network.request',return_value=(503,[],b'')):
            findings,assets,events=scan_web('http://127.0.0.1/',scope,lambda *_:None)
            self.assertFalse(findings);self.assertEqual(assets[0]['status'],503);self.assertIn('instability',events[0])

    def test_invalid_source_and_traversal_budgets(self):
        with self.assertRaises(PolicyError):source_scan('/does-not-exist',Config(),lambda *_:None)
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'bad.py').write_text('this is not valid python!!!')
            _,_,_,events=source_scan(p,Config(),lambda *_:None);self.assertIn('syntax',events[0])
            (p/'other.py').write_text('x=1')
            for cfg in (Config(max_files=1),Config(max_file_bytes=2),Config(max_total_bytes=2)):
                with self.assertRaises(PolicyError):source_scan(p,cfg,lambda *_:None)

    def test_report_write_failure_has_nonzero_cli_exit(self):
        script="""from unittest.mock import patch
from secaudit.cli import main
import sys
with patch('secaudit.cli.reports',side_effect=OSError('simulated disk failure')):
 raise SystemExit(main(['scan','--source',sys.argv[1],'--output',sys.argv[2]]))
"""
        with tempfile.TemporaryDirectory() as t:
            p=subprocess.run([sys.executable,'-c',script,str(ROOT/'demo/source'),t],cwd=ROOT,capture_output=True,text=True,timeout=20)
            self.assertNotEqual(p.returncode,0);self.assertNotIn('Traceback',p.stderr)
            runs=list(Path(t).glob('*/partial.json'));self.assertTrue(runs)

if __name__=='__main__':unittest.main()
