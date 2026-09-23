"""Real Semgrep acceptance with local rules, no network and no mocked output."""
import hashlib
import json
import platform
import tempfile
from pathlib import Path

from secaudit.adapters import execute, probe
from secaudit.models import now
from secaudit.security import PolicyError, write_json

EXE = '/usr/local/lib/secaudit-semgrep/bin/semgrep'
RULES = '''rules:
  - id: acceptance-python-eval
    languages: [python]
    message: Review dynamic evaluation
    severity: WARNING
    pattern: eval(...)
  - id: acceptance-js-innerhtml
    languages: [javascript]
    message: Review HTML assignment
    severity: WARNING
    pattern: $EL.innerHTML = $VALUE
'''


def main():
    result = {'started': now(), 'status': 'FAILED', 'host': platform.platform(),
              'tool': 'semgrep', 'expected_version': '1.175.0',
              'scope': 'Two local fixture rules; no general ruleset effectiveness claim'}
    try:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root/'source'
            source.mkdir()
            rules = root/'rules.yaml'
            rules.write_text(RULES)
            options = {'executable': EXE, 'rules': str(rules)}
            result['stage'] = 'version-probe'
            _, version = probe('semgrep', options)
            if version != result['expected_version']:
                raise RuntimeError('Unexpected Semgrep version')
            result['version'] = version
            result['rules_sha256'] = hashlib.sha256(rules.read_bytes()).hexdigest()
            (source/'app.py').write_text('eval(input())\n')
            (source/'app.js').write_text('element.innerHTML = userInput;\n')
            # Project-provided rule configuration must not replace operator rules.
            (source/'.semgrep.yml').write_text('rules: []\n')
            result['stage'] = 'positive-control'
            findings, _ = execute('semgrep', source, options, 60)
            if len(findings) != 2 or {f.asset for f in findings} != {'app.py', 'app.js'}:
                raise RuntimeError('Expected both Python and JavaScript findings')
            result['positive_findings'] = len(findings)
            (source/'app.py').write_text('print("hello")\n')
            (source/'app.js').write_text('element.textContent = userInput;\n')
            result['stage'] = 'clean-control'
            clean, _ = execute('semgrep', source, options, 60)
            if clean:
                raise RuntimeError('Clean control unexpectedly flagged')
            result['clean_findings'] = 0
            result['stage'] = 'invalid-rules-control'
            rules.write_text('rules: [unterminated\n')
            try:
                execute('semgrep', source, options, 30)
            except PolicyError:
                result['invalid_rules'] = 'rejected'
            else:
                raise RuntimeError('Invalid rules produced a clean result')
            result['status'] = 'PASSED'
    except Exception as error:
        result['failure_type'] = type(error).__name__
        if isinstance(error, PolicyError):
            result['policy_failure'] = str(error)
    result['finished'] = now()
    output = Path('artifacts/semgrep')
    output.mkdir(parents=True, exist_ok=True)
    write_json(output/'acceptance.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
