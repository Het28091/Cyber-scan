"""Build reviewable archives; does not tag or publish a release."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
import tarfile
import tempfile
import subprocess

from secaudit import __version__
from secaudit.bundle import prepare, verify, SOURCE_PATHS
from secaudit.release_gate import verify as verify_acceptance


def verify_source(root,commit):
    root=Path(root)
    for name in SOURCE_PATHS:
        path=root/name
        if path.is_symlink() or path.is_dir() and any(p.is_symlink() for p in path.rglob('*')):raise ValueError('linked release source inputs are forbidden')
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    if actual!=commit:raise ValueError('source commit does not match the checkout')
    changes=subprocess.check_output(['git','status','--porcelain','--untracked-files=all','--',*SOURCE_PATHS],cwd=root,text=True)
    if changes.strip():raise ValueError('release source contains uncommitted or untracked inputs')
    ignored=subprocess.check_output(['git','ls-files','--others','--ignored','--exclude-standard','--',*SOURCE_PATHS],cwd=root,text=True)
    if any('__pycache__' not in Path(name).parts and not name.endswith('.pyc') for name in ignored.splitlines()):raise ValueError('ignored files would enter the release source; remove them from packaged directories')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', required=True)
    dependencies=parser.add_mutually_exclusive_group()
    dependencies.add_argument('--with-wheels', action='store_true')
    dependencies.add_argument('--wheelhouse', help='Prepared local locked wheels; no network fallback')
    parser.add_argument('--channel', choices=['candidate', 'stable'], default='candidate')
    parser.add_argument('--acceptance-manifest',help='Required for stable builds; generated after the exact source commit')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.commit):
        parser.error('--commit must be the full source commit SHA')
    verify_source(Path(__file__).resolve().parents[1],args.commit)
    acceptance=None
    if args.channel=='stable':
        if not args.acceptance_manifest:parser.error('stable builds require --acceptance-manifest; build a candidate until acceptance passes')
        acceptance=verify_acceptance(args.acceptance_manifest,args.commit,__version__)
    output = Path(args.output).resolve()
    if output.exists():
        parser.error('--output must be a new directory')
    output.mkdir(parents=True)
    name = f'secaudit-{__version__}-{args.channel}-{args.commit[:12]}-linux-{platform.machine()}-py{sys.version_info.major}.{sys.version_info.minor}'
    with tempfile.TemporaryDirectory() as temporary:
        bundle = Path(temporary) / name
        manifest = prepare(bundle, args.with_wheels, args.wheelhouse)
        verify(bundle)
        # Keep metadata outside the installer's strict bundle manifest.
        metadata = {'app_version': __version__, 'source_commit': args.commit, 'release_channel': args.channel,
                    'platform': 'Linux', 'architecture': platform.machine(),
                    'python': list(sys.version_info[:2]), 'pdf_wheels': manifest['pdf_wheels'],
                    'authenticity': 'Unsigned checksums detect corruption, not publisher authenticity',
                    'scope': 'Governance and orchestration; no exhaustive pentest or compliance certification'}
        if acceptance:metadata['acceptance_manifest_sha256']=acceptance['manifest_sha256']
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
