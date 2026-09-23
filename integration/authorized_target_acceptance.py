"""Explicit one-page acceptance for the owner's authorized Grid Guard deployment.

Not part of recurring tests. No scripts, forms, credentials or linked paths executed.
"""
import ipaddress
import json
import platform
import socket
import tempfile
from pathlib import Path

from secaudit.cli import scan
from secaudit.config import Config
from secaudit.models import now
from secaudit.security import write_json

TARGET = 'https://grid-guard-ai-ibm.vercel.app/login'


def main():
    result = {'started': now(), 'status': 'FAILED', 'target': TARGET,
              'authorization': 'Project owner explicitly authorized this deployment in the maintainer session, 2026-09-23.',
              'profile': 'Unauthenticated passive GET/HEAD; login page only',
              'host': platform.platform(), 'request_budget': {'preflight_HEAD': 1, 'crawl_GET': 1},
              'limitations': ['No JavaScript execution, login, form submission or account changes',
                              'No authenticated, backend or business-logic coverage',
                              'Findings are candidate deployment-header observations, not proof of exploitability']}
    try:
        ips = sorted({r[4][0] for r in socket.getaddrinfo('grid-guard-ai-ibm.vercel.app', 443, type=socket.SOCK_STREAM)})
        if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
            raise RuntimeError('External acceptance requires public DNS addresses')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scope = {'authorization': result['authorization'], 'origins': [TARGET], 'exclusions': [],
                     'environment': 'owner-authorized-external-acceptance', 'profiles': ['passive'],
                     'allowed_ips': ips, 'max_requests': 1, 'max_seconds': 10}
            write_json(root / 'scope.json', scope)
            cfg = Config(mode='internet', target=TARGET, scope=str(root/'scope.json'),
                         output=str(root/'runs'), modules=['web'], timeout=30, pdf_required=True).validate()
            exit_code = scan(cfg)
            runs = list((root/'runs').glob('*/run.json'))
            if exit_code or len(runs) != 1:
                raise RuntimeError('Assessment did not finish')
            run = json.loads(runs[0].read_text())
            if run['status'] != 'COMPLETED_WITH_LIMITATIONS' or len(run['assets']) != 1:
                raise RuntimeError('Expected one completed page assessment')
            asset = run['assets'][0]
            if asset['asset'] != TARGET or asset['status'] != 200:
                raise RuntimeError('Login page did not return HTTP 200')
            for filename in ('executive.pdf', 'technical.pdf'):
                if not (runs[0].parent/filename).read_bytes().startswith(b'%PDF-'):
                    raise RuntimeError('PDF report missing')
            result.update(status='PASSED', http_status=asset['status'], assets=len(run['assets']),
                          finding_count=len(run['findings']),
                          findings=[{'rule': f['rule'], 'severity': f['severity'], 'title': f['title']} for f in run['findings']],
                          coverage=run['coverage'], ai_enabled=run['ai_usage']['enabled'], pdf_reports='passed')
    except Exception as error:
        result['failure_type'] = type(error).__name__
    result['finished'] = now()
    output = Path('artifacts/authorized-target')
    output.mkdir(parents=True, exist_ok=True)
    # Do not publish page bodies, cookies, raw reports or authentication material.
    write_json(output/'acceptance.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
