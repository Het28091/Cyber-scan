"""Real inventory adapters: connected preparation, network-isolated assessment."""
import hashlib
import json
import platform
import sys
import tempfile
from pathlib import Path

from secaudit.adapters import execute, probe
from secaudit import adapters
from secaudit.cli import scan
from secaudit.config import Config
from secaudit.models import now
from secaudit.security import PolicyError, write_json


def main(name, cache=None):
    expected = {'syft': '1.52.0', 'trivy': '0.74.0'}[name]
    result = {'started': now(), 'status': 'FAILED', 'tool': name,
              'expected_version': expected, 'host': platform.platform(),
              'scope': 'Synthetic npm lockfile; no package installation or target traffic'}
    original_bounded = adapters.bounded

    def fixture_bounded(command, *args, **kwargs):
        # This harness mounts synthetic inputs only. Never enable raw diagnostics
        # in production scanning: they may contain source or credentials.
        code, raw = original_bounded(command, *args, **kwargs)
        if code and '--' in command:
            split = command.index('--') + 1
            diagnostic_command = command[:split] + ['/bin/sh', '-c', 'exec "$@" 2>&1', 'fixture'] + command[split:]
            diagnostic_code, diagnostic = original_bounded(diagnostic_command, *args, **kwargs)
            result['fixture_exit_code'] = diagnostic_code
            result['fixture_diagnostic'] = diagnostic.decode('utf-8', 'replace')[-8000:]
        return code, raw

    adapters.bounded = fixture_bounded
    try:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root/'source'
            source.mkdir()
            options = {'executable': '/usr/local/bin/'+name}
            if name == 'trivy':
                options['cache'] = str(Path(cache).resolve())
                db = Path(cache)/'db/trivy.db'
                with db.open('rb') as stream:
                    result['database_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
                result['database_metadata'] = json.loads((db.parent/'metadata.json').read_text())
            result['stage'] = 'version-probe'
            _, version = probe(name, options)
            if version != expected:
                raise RuntimeError('Unexpected tool version')
            result['version'] = version
            (source/'package.json').write_text(json.dumps({'name': 'acceptance', 'version': '1.0.0', 'dependencies': {'lodash': '4.17.20'}}))
            lock = {'name': 'acceptance', 'version': '1.0.0', 'lockfileVersion': 2,
                    'requires': True, 'packages': {'': {'name': 'acceptance', 'version': '1.0.0', 'dependencies': {'lodash': '4.17.20'}},
                    'node_modules/lodash': {'version': '4.17.20', 'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'}},
                    'dependencies': {'lodash': {'version': '4.17.20'}}}
            (source/'package-lock.json').write_text(json.dumps(lock))
            result['stage'] = 'positive-control'
            findings, sbom = execute(name, source, options, 120)
            if name == 'syft':
                matches = [c for c in sbom.get('components', []) if c.get('name') == 'lodash' and c.get('version') == '4.17.20']
                if not matches:
                    raise RuntimeError('Expected lodash inventory component')
                result['matched_components'] = len(matches)
            else:
                if not any(f.rule == 'TRIVY-CVE-2021-23337' for f in findings):
                    raise RuntimeError('Expected known lodash advisory')
                result['positive_findings'] = len(findings)
            result['stage'] = 'empty-control'
            empty = root/'empty'
            empty.mkdir()
            clean, clean_sbom = execute(name, empty, options, 120)
            if clean or (name == 'syft' and clean_sbom.get('components')):
                raise RuntimeError('Empty input produced findings or components')
            result['empty_control'] = 'passed'
            if name == 'trivy':
                result['stage'] = 'missing-database-control'
                try:
                    execute(name, source, {**options, 'cache': str(root/'missing')}, 30)
                except PolicyError:
                    result['missing_database'] = 'rejected'
                else:
                    raise RuntimeError('Missing database accepted')
                result['stage'] = 'corrupt-database-control'
                corrupt = root/'corrupt/db'
                corrupt.mkdir(parents=True)
                (corrupt/'trivy.db').write_bytes(b'invalid database')
                (corrupt/'metadata.json').write_text((Path(cache)/'db/metadata.json').read_text())
                try:
                    execute(name, source, {**options, 'cache': str(corrupt.parent)}, 30)
                except PolicyError:
                    result['corrupt_database'] = 'rejected'
                else:
                    raise RuntimeError('Corrupt database accepted')
            result['stage'] = 'reporting-pipeline' 
            cfg = Config(mode='offline', source=str(source), output=str(root/'runs'),
                         modules=[name], scanners={name: options}, strict=True,
                         pdf_required=True).validate()
            if scan(cfg):
                raise RuntimeError('Reporting pipeline failed')
            run_path = next((root/'runs').glob('*/run.json'))
            run = json.loads(run_path.read_text())
            if name == 'syft':
                emitted = json.loads((run_path.parent/'external-sbom.cdx.json').read_text())
                if not any(c.get('name') == 'lodash' for c in emitted.get('components', [])):
                    raise RuntimeError('External SBOM missing component')
            elif not run['findings']:
                raise RuntimeError('Pipeline lost findings')
            for filename in ('executive.pdf', 'technical.pdf'):
                if not (run_path.parent/filename).read_bytes().startswith(b'%PDF-'):
                    raise RuntimeError('PDF output unavailable')
            result['pipeline'] = {'pdf_reports': 'passed', 'ai_enabled': run['ai_usage']['enabled']}
            result['status'] = 'PASSED'
    except Exception as error:
        result['failure_type'] = type(error).__name__
        result['failure'] = str(error)
    finally:
        adapters.bounded = original_bounded
    result['finished'] = now()
    output = Path('artifacts')/name
    output.mkdir(parents=True, exist_ok=True)
    write_json(output/'acceptance.json', result)
    print(json.dumps(result, indent=2))
    return int(result['status'] != 'PASSED')


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
