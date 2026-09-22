"""Explicit live acceptance: one OSV query and real isolated Gitleaks execution.

Run with PYTHONPATH=. python integration/live_acceptance.py on a prepared Linux host.
No mocks, retries, skip-on-unavailable behavior or sandbox policy overrides.
"""
import hashlib
import json
import os
import platform
import shutil
import socket
import tempfile
from pathlib import Path
from secaudit.adapters import bounded, execute, probe, sandbox_command
from secaudit.config import Config
from secaudit.models import now
from secaudit.security import PolicyError
from secaudit.online import scan_dependencies


def verify():
    result = {'started': now(), 'platform': platform.platform(), 'status': 'FAILED'}
    try:
        cfg = Config(mode='internet', online_package_limit=1, timeout=20)
        findings, usage, _ = scan_dependencies(
            [{'name': 'requests', 'version': '2.19.1', 'purl': 'pkg:pypi/requests@2.19.1'}], cfg)
        result['osv'] = {'requests': usage['requests'], 'responses': usage['responses'],
                         'completed': usage['completed'], 'failed': usage['failed'],
                         'skipped': usage['skipped'], 'advisories': len(findings)}
        if usage['requests'] != 1 or usage['completed'] != 1 or usage['failed'] or usage['skipped'] or not findings:
            raise RuntimeError('Live OSV acceptance did not complete')
        result['stage']='scanner-preflight'
        # Fixed version command only: no source mount or inherited credentials.
        # Retain bounded startup diagnostics to distinguish runtime incompatibility.
        code, startup = bounded(sandbox_command('/bin/sh') + ['-c', '/usr/local/bin/gitleaks version 2>&1'], 10, 65536)
        if code:
            result['startup_diagnostic']=startup.decode('utf-8','replace')[:2000]
        exe, version = probe('gitleaks', {})
        result['tool'] = {'name': 'gitleaks', 'version': version,
                          'sha256': hashlib.sha256(Path(exe).read_bytes()).hexdigest()}
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'source'
            source.mkdir()
            # Deliberately synthetic, never an issued credential.
            (source / 'fixture.py').write_text('api_key = "ghp_Ab7cD8eF9gH0iJ1kL2mN3oP4qR5sT6uV7wX8"\n')
            result['stage']='scanner-positive-control'
            detected, _ = execute('gitleaks', source, {}, 45)
            if not detected:
                raise RuntimeError('Real scanner missed the synthetic secret')
            result['tool']['fixture_findings'] = len(detected)
            (source / 'fixture.py').write_text('print("hello")\n')
            result['stage']='scanner-negative-control'
            clean, _ = execute('gitleaks', source, {}, 45)
            if clean:
                raise RuntimeError('Real scanner flagged the clean control')
            result['tool']['clean_control_findings'] = len(clean)
            listener = socket.socket()
            try:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                port = listener.getsockname()[1]
                os.environ['SECAUDIT_TARGET_ACCEPTANCE'] = 'synthetic-not-for-child'
                result['stage']='sandbox-boundaries'
                script = """import os,socket
assert 'SECAUDIT_TARGET_ACCEPTANCE' not in os.environ
s=socket.socket();s.settimeout(1)
assert s.connect_ex(('127.0.0.1',PORT)) != 0
try: open('/input/should-not-exist','w')
except OSError: pass
else: raise AssertionError('source writable')
assert int(next(x.split(':')[1].strip() for x in open('/proc/self/status') if x.startswith('CapEff:')),16)==0
""".replace('PORT', str(port))
                code, _ = bounded(sandbox_command('/usr/bin/python3', source) + ['-c', script], 5)
                if code:
                    raise RuntimeError('Sandbox boundary acceptance failed')
                result['sandbox'] = {'network_namespace': 'PASS', 'source_read_only': 'PASS',
                                     'credential_environment_removed': 'PASS', 'capabilities_dropped': 'PASS',
                                     'bubblewrap': shutil.which('bwrap')}
            finally:
                listener.close()
                os.environ.pop('SECAUDIT_TARGET_ACCEPTANCE', None)
        result['status'] = 'PASSED'
    except Exception as exc:
        result['failure_type'] = type(exc).__name__
        if isinstance(exc,PolicyError): result['policy_failure']=str(exc)
        # No raw tool/provider output or credentials in acceptance logs.
    result['finished'] = now()
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(verify())
