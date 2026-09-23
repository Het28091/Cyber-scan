"""Verify CI bundles before collecting stable GitHub release assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from secaudit import __version__


def main():
    commit = os.environ['GITHUB_SHA']
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('invalid commit')
    incoming = Path('incoming')
    output = Path('release-assets')
    output.mkdir(exist_ok=False)
    seen = set()
    for metadata_path in sorted(incoming.glob('*/release.json')):
        folder = metadata_path.parent
        metadata = json.loads(metadata_path.read_text())
        minor = tuple(metadata['python'])
        if (metadata['source_commit'] != commit or metadata['app_version'] != __version__
                or metadata['release_channel'] != 'stable' or not metadata['pdf_wheels']
                or metadata['architecture'] != 'x86_64' or metadata['platform'] != 'Linux'
                or minor not in {(3, 11), (3, 12), (3, 13), (3, 14)} or minor in seen):
            raise ValueError('release metadata mismatch')
        seen.add(minor)
        for line in (folder/'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            if Path(name).name != name:
                raise ValueError('unsafe checksum path')
            with (folder/name).open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                    raise ValueError('archive checksum mismatch')
        archives = list(folder.glob('*.tar.gz'))
        if len(archives) != 1:
            raise ValueError('expected one archive')
        with tarfile.open(archives[0]) as archive:
            manifests = [n for n in archive.getnames() if n.endswith('/manifest.json')]
            if len(manifests) != 1:
                raise ValueError('expected one bundle manifest')
            manifest = json.load(archive.extractfile(manifests[0]))
            prefix = manifests[0].rsplit('/', 1)[0]
            if manifest['app_version'] != __version__:
                raise ValueError('bundle version mismatch')
            for name, digest in manifest['files'].items():
                with archive.extractfile(prefix+'/'+name) as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                        raise ValueError('bundle checksum mismatch')
        shutil.copyfile(archives[0], output/archives[0].name)
        shutil.copyfile(metadata_path, output/f'release-python{minor[0]}.{minor[1]}.json')
    if len(seen) != 4:
        raise ValueError('all four supported Python bundles are required')
    subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=secaudit-'+__version__+'/',
                    '-o', str(output/f'secaudit-{__version__}-source.tar.gz'), commit], check=True)
    checksums = []
    for path in sorted(output.iterdir()):
        with path.open('rb') as stream:
            checksums.append(hashlib.file_digest(stream, 'sha256').hexdigest()+'  '+path.name)
    (output/'SHA256SUMS').write_text('\n'.join(checksums)+'\n')


if __name__ == '__main__':
    main()
