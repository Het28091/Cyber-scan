"""Build reviewable candidate archives; does not tag or publish a stable release."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
import tarfile
import tempfile

from secaudit import __version__
from secaudit.bundle import prepare, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--with-wheels', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.commit):
        parser.error('--commit must be the full source commit SHA')
    output = Path(args.output).resolve()
    if output.exists():
        parser.error('--output must be a new directory')
    output.mkdir(parents=True)
    name = f'secaudit-{__version__}-candidate-{args.commit[:12]}-linux-{platform.machine()}-py{sys.version_info.major}.{sys.version_info.minor}'
    with tempfile.TemporaryDirectory() as temporary:
        bundle = Path(temporary) / name
        manifest = prepare(bundle, args.with_wheels)
        verify(bundle)
        # Keep metadata outside the installer's strict bundle manifest.
        metadata = {'app_version': __version__, 'source_commit': args.commit, 'release_channel': 'candidate',
                    'platform': 'Linux', 'architecture': platform.machine(),
                    'python': list(sys.version_info[:2]), 'pdf_wheels': manifest['pdf_wheels'],
                    'authenticity': 'Unsigned checksums detect corruption, not publisher authenticity',
                    'scope': 'Governance and orchestration; no exhaustive pentest or compliance certification'}
        archive = output / (name + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as tar:
            tar.add(bundle, arcname=name)
        (output / 'release.json').write_text(json.dumps(metadata, indent=2) + '\n')
        checksums = []
        for path in sorted(output.iterdir()):
            with path.open('rb') as stream:
                checksums.append(hashlib.file_digest(stream, 'sha256').hexdigest() + '  ' + path.name)
        (output / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
    print(json.dumps({'output': str(output), **metadata}))


if __name__ == '__main__':
    main()
