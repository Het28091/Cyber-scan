"""Verify CI bundles before collecting stable GitHub release assets."""
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

from secaudit import __version__
from secaudit.bundle import ALLOWED
from secaudit.release_gate import verify as verify_acceptance


def verify_checksums(folder):
    """Require complete, unique checksums for the metadata and delivered archive."""
    listing=folder/'SHA256SUMS'
    if listing.is_symlink() or not listing.is_file() or listing.stat().st_size>65536:raise ValueError('invalid checksum list')
    expected={'release.json'}|{p.name for p in folder.glob('*.tar.gz')}
    if len(expected)!=2:raise ValueError('expected one release archive')
    seen=set()
    for line in listing.read_text().splitlines():
        digest,name=line.split('  ',1)
        if not re.fullmatch('[a-f0-9]{64}',digest) or name not in expected or name in seen or Path(name).name!=name or '\\' in name:raise ValueError('invalid or duplicate checksum entry')
        path=folder/name
        if path.is_symlink() or not path.is_file():raise ValueError('invalid release artifact')
        with path.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=digest:raise ValueError('archive checksum mismatch')
        seen.add(name)
    if seen!=expected:raise ValueError('incomplete release checksums')


def verify_archive(path):
    with tarfile.open(path) as archive:
        entries={};total=0
        for entry in archive:
            total+=entry.size
            if len(entries)>=20000 or entry.size>512_000_000 or total>2_000_000_000:raise ValueError('release archive resource limit exceeded')
            parts=PurePosixPath(entry.name)
            if entry.name in entries or parts.is_absolute() or any(p in ('','.','..') for p in entry.name.split('/')) or '\\' in entry.name or ':' in entry.name or not (entry.isfile() or entry.isdir()):raise ValueError('unsafe or duplicate archive member')
            entries[entry.name]=entry
        manifests=[e for n,e in entries.items() if n.endswith('/manifest.json') and e.isfile()]
        if len(manifests)!=1 or manifests[0].size>5_000_000:raise ValueError('expected one bounded bundle manifest')
        with archive.extractfile(manifests[0]) as stream:manifest=json.load(stream)
        prefix=manifests[0].name.rsplit('/',1)[0]
        if not isinstance(manifest,dict):raise ValueError('invalid bundle manifest')
        files=manifest.get('files')
        if manifest.get('app_version')!=__version__ or not isinstance(files,dict) or not set(ALLOWED)<=set(files):raise ValueError('invalid bundle manifest')
        expected={manifests[0].name}
        for name,digest in files.items():
            parts=PurePosixPath(name)
            if name not in ALLOWED and not (len(parts.parts)==2 and parts.parts[0]=='wheelhouse' and parts.suffix=='.whl'):raise ValueError('unexpected bundle file')
            if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest) or parts.is_absolute() or '..' in parts.parts or '\\' in name or ':' in name:raise ValueError('unsafe bundle manifest entry')
            member=prefix+'/'+name;expected.add(member)
            if member not in entries or not entries[member].isfile():raise ValueError('missing bundle file')
            with archive.extractfile(entries[member]) as stream:
                if hashlib.file_digest(stream,'sha256').hexdigest()!=digest:raise ValueError('bundle checksum mismatch')
        if {n for n,e in entries.items() if e.isfile()}!=expected:raise ValueError('unmanifested archive files')


def main():
    commit = os.environ['GITHUB_SHA']
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('invalid commit')
    acceptance=verify_acceptance(os.environ.get('SECAUDIT_ACCEPTANCE_MANIFEST','artifacts/acceptance/manifest.json'),commit,__version__)
    incoming = Path('incoming')
    output = Path('release-assets')
    if incoming.is_symlink():raise ValueError('linked incoming directory forbidden')
    if output.exists() or output.is_symlink():raise ValueError('release-assets must not exist')
    with tempfile.TemporaryDirectory(prefix='secaudit-release-',dir='.') as temporary:
        stage=Path(temporary)/'assets';stage.mkdir()
        collect(incoming,stage,commit,acceptance)
        os.replace(stage,output)


def collect(incoming,output,commit,acceptance):
    seen = set()
    for metadata_path in sorted(incoming.glob('*/release.json')):
        folder = metadata_path.parent
        if folder.is_symlink():raise ValueError('linked release directory forbidden')
        verify_checksums(folder)
        metadata = json.loads(metadata_path.read_text())
        minor = tuple(metadata['python'])
        if (metadata['source_commit'] != commit or metadata['app_version'] != __version__
                or metadata['release_channel'] != 'stable' or not metadata['pdf_wheels']
                or metadata.get('acceptance_manifest_sha256')!=acceptance['manifest_sha256']
                or metadata['architecture'] != 'x86_64' or metadata['platform'] != 'Linux'
                or minor not in {(3, 11), (3, 12), (3, 13), (3, 14)} or minor in seen):
            raise ValueError('release metadata mismatch')
        seen.add(minor)
        archives = list(folder.glob('*.tar.gz'))
        if len(archives) != 1:
            raise ValueError('expected one archive')
        verify_archive(archives[0])
        shutil.copyfile(archives[0], output/archives[0].name)
        shutil.copyfile(metadata_path, output/f'release-python{minor[0]}.{minor[1]}.json')
    if len(seen) != 4:
        raise ValueError('all four supported Python bundles are required')
    (output/'acceptance-verification.json').write_text(json.dumps(acceptance,indent=2)+'\n')
    subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=secaudit-'+__version__+'/',
                    '-o', str(output/f'secaudit-{__version__}-source.tar.gz'), commit], check=True)
    checksums = []
    for path in sorted(output.iterdir()):
        with path.open('rb') as stream:
            checksums.append(hashlib.file_digest(stream, 'sha256').hexdigest()+'  '+path.name)
    (output/'SHA256SUMS').write_text('\n'.join(checksums)+'\n')


if __name__ == '__main__':
    main()
