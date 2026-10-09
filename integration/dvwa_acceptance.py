"""Explicit owner DVWA lab check. Never run automatically or follow links/forms.

Run on the authorized Kali VM: .venv/bin/python -m integration.dvwa_acceptance
An independent single GET checks cookie flags; values and response bodies are not saved.
"""
import http.client
import json
import platform
import subprocess
from pathlib import Path

from secaudit.cli import scan
from secaudit.config import Config
from secaudit.models import now
from secaudit.security import write_json

TARGET='http://10.87.119.94:8080/security.php'


def main():
    root=Path('artifacts/checkpoints/dvwa-oct9')
    root.mkdir(parents=True,exist_ok=True)
    scope=dict(authorization='Owner explicitly requested this DVWA assessment on 2026-10-09',
               origins=[TARGET], exclusions=[], environment='owner-dvwa', profiles=['passive'],
               allowed_ips=['10.87.119.94'], max_requests=1, max_seconds=10)
    write_json(root/'scope.json',scope)
    code=scan(Config(mode='internet',target=TARGET,scope=str(root/'scope.json'),
                     output=str(root/'runs'),modules=['web'],timeout=30,pdf_required=True).validate())
    path=max((root/'runs').glob('*/run.json'),key=lambda p:p.stat().st_mtime)
    run=json.loads(path.read_text())
    # Independent transport/parser, no redirects or cookie jar. Literal owner IP only.
    conn=http.client.HTTPConnection('10.87.119.94',8080,timeout=5)
    try:
        conn.request('GET','/security.php',headers={'User-Agent':'Secaudit-owner-validation'})
        response=conn.getresponse()
        status=response.status
        cookies=response.headers.get_all('Set-Cookie',[])
        expected=set()
        for cookie in cookies:
            attrs={part.strip().partition('=')[0].casefold() for part in cookie.split(';')[1:]}
            missing={'secure','httponly','samesite'}-attrs
            if missing: expected.add('Cookie lacks '+', '.join(sorted(missing)))
    finally:
        conn.close()
    actual={f['description'] for f in run['findings'] if f['rule']=='COOKIE-FLAGS'}
    pdf_ok=all((path.parent/name).read_bytes().startswith(b'%PDF-') for name in ('technical.pdf','executive.pdf'))
    passed=code==0 and run['assets']==[{'asset':TARGET,'status':status}] and actual==expected and pdf_ok
    summary=dict(timestamp=now(),source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                 host=platform.platform(),status='PASS' if passed else 'FAIL',target=TARGET,
                 request_budget={'scanner_HEAD':1,'scanner_GET':1,'independent_GET':1},
                 run_id=run['id'],run_status=run['status'],assets=run['assets'],coverage=run['coverage'],events=run['events'],
                 findings=[{'rule':f['rule'],'description':f['description']} for f in run['findings']],
                 cookie_check={'expected_unique_observations':len(expected),'true_positives':len(actual & expected),
                               'false_positives':len(actual-expected),'false_negatives':len(expected-actual)},
                 pdf_reports=pdf_ok,ai_enabled=run['ai_usage']['enabled'],
                 limitations=['Comparison covers cookie-flag observations on two consecutive responses only; deployment may change.',
                              'No login, forms, payloads, SQL injection, XSS or command execution tested.',
                              'Not a whole-DVWA precision/recall measurement; duplicate cookie findings are consolidated.'])
    write_json(root/'acceptance.json',summary)
    print(json.dumps(summary,indent=2))
    return 0 if passed else 1


if __name__=='__main__':
    raise SystemExit(main())
