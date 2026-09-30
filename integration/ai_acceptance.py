"""Explicit operator invocation: exercise a prepared real provider, never download.

Run on Linux with SECAUDIT_EXPERIMENTAL_AI=1 and a reviewed config. The normal
scan path performs readiness, inference, persistence and report generation.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from secaudit.config import load
from secaudit.security import PolicyError,write_json


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    parser.add_argument('--evidence',required=True)
    args=parser.parse_args()
    cfg=load(args.config)
    if not cfg.ai.enabled or cfg.ai.failure_policy!='required': raise PolicyError('Acceptance requires enabled AI and failure_policy=required')
    if cfg.target or not cfg.source: raise PolicyError('Use a synthetic source fixture without a deployed target for provider acceptance')
    result=subprocess.run([sys.executable,'-m','secaudit','scan','--config',args.config],capture_output=True,text=True,timeout=cfg.timeout+180)
    if result.returncode: raise PolicyError('Provider acceptance failed; inspect local preflight and partial evidence')
    try:
        output=json.loads(result.stdout)
        directory=Path(output['reports'])
        run=json.loads((directory/'run.json').read_text())
        suggestions=json.loads((directory/'ai-suggestions.json').read_text())
        valid=(run['status']=='COMPLETED_WITH_LIMITATIONS' and bool(run['findings']) and bool(suggestions['suggestions'])
            and run['ai_usage']['verified']=='inference response validated'
            and all(item['id'] in {f['id'] for f in run['findings']} for item in suggestions['suggestions'])
            and all((directory/name).is_file() for name in ('technical.html','technical.md','findings.json','preflight_report.json')))
        if not valid: raise PolicyError('Provider acceptance evidence incomplete')
    except (ValueError,KeyError,OSError,TypeError): raise PolicyError('Provider acceptance evidence incomplete') from None
    write_json(args.evidence,{'status':'PASS','kind':'operator-configured provider acceptance','mode':cfg.mode,
        'model':cfg.ai.model,'run_id':run['id'],'usage':run['ai_usage'],
        'limitation':'Operator must identify the actual prepared provider/runtime. This result does not authorize broader data disclosure.'})


if __name__=='__main__':
    try:main()
    except (PolicyError,subprocess.TimeoutExpired):
        print('AI acceptance failed; no provider response or credential logged.',file=sys.stderr);raise SystemExit(1)
