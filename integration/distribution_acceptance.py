"""Install a wheel bundle with inherited seccomp network denial, then run it."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from secaudit.bundle import install, prepare
from secaudit.security import deny_network


def main():
    with tempfile.TemporaryDirectory(prefix='secaudit distribution ') as temp:
        root = Path(temp)
        bundle = root / 'bundle'
        manifest = prepare(bundle, download_dependencies=True)
        # This filter is inherited by venv, pip and the installed CLI. No online fallback.
        deny_network()
        destination = root / 'installed app'
        install(bundle, destination)
        output = root / 'assessment'
        config = root / 'config.json'
        source = root / 'owned source'
        source.mkdir()
        (source / 'app.py').write_text('eval(input())\n')
        config.write_text(json.dumps({'mode': 'offline', 'source': str(source), 'output': str(output),
                                     'modules': ['source', 'secrets', 'config', 'dependencies', 'openapi']}))
        subprocess.run([str(destination / 'secaudit'), 'scan', '--config', str(config)],
                       check=True, cwd=root, timeout=90)
        runs = list(output.glob('*/run.json'))
        assert len(runs) == 1, 'Expected one installed assessment'
        run = json.loads(runs[0].read_text())
        assert run['findings'], 'Synthetic eval fixture was not detected'
        for name in ('executive.pdf', 'technical.pdf'):
            assert (runs[0].parent / name).read_bytes().startswith(b'%PDF-'), name
        assert json.loads((runs[0].parent / 'sbom.cdx.json').read_text())['bomFormat'] == 'CycloneDX'
        print(json.dumps({'status': 'passed', 'python': sys.version, 'architecture': manifest['architecture'],
                          'offline_install': 'seccomp network denied', 'pdf_reports': 'passed',
                          'paths_with_spaces': 'passed', 'working_directory_independence': 'passed'}))


if __name__ == '__main__':
    main()
