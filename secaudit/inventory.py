"""Bounded declaration inventory, never an installer or dependency resolver."""
import json
import re
from pathlib import Path
from urllib.parse import quote


def parse_manifest(name, text):
    """Return exact-version components and quantified unresolved declarations."""
    stats = dict(asset=name, type='dependency-inventory', total=0, pinned=0,
                 unresolved=0, invalid=0, unsupported=0, conditional=0, issues=[])
    components = []

    def issue(kind, position, reason):
        stats[kind] += 1
        # Never retain raw requirement text: it may contain URL credentials.
        if len(stats['issues']) < 50:
            stats['issues'].append(dict(position=position, status=kind, reason=reason))

    def component(package, version, ecosystem):
        components.append(dict(name=package, version=version, type='library',
                               purl=f'pkg:{ecosystem}/{quote(package, safe="/")}@{quote(version, safe="")}'))
        stats['pinned'] += 1

    if Path(name).name.startswith('requirements') and Path(name).suffix in ('.txt', '.in', '.lock'):
        try:
            from packaging.requirements import Requirement, InvalidRequirement
            from packaging.utils import canonicalize_name
        except ImportError:
            Requirement = None
        logical = re.sub(r'\\\r?\n', ' ', text)
        for position, raw in enumerate(logical.splitlines(), 1):
            line = re.split(r'\s+#', raw.strip(), maxsplit=1)[0].strip()
            if not line or line.startswith('#'):
                continue
            stats['total'] += 1
            if line.startswith('-'):
                issue('unsupported', position, 'Directive/include not followed; inventory is incomplete')
                continue
            if Requirement is None:
                issue('unsupported', position, 'packaging parser unavailable; run setup')
                continue
            # Hashes constrain installation; they do not identify a version.
            line = re.sub(r'\s+--hash=\S+', '', line)
            try:
                req = Requirement(line)
            except InvalidRequirement:
                issue('invalid', position, 'Invalid requirement syntax')
                continue
            if req.marker:
                stats['conditional'] += 1
            versions = list(req.specifier)
            if req.url or len(versions) != 1 or versions[0].operator != '==' or '*' in versions[0].version:
                issue('unresolved', position, 'No single exact version; supply a resolved lockfile')
                continue
            # Retain conditional pins conservatively: the scanner host is not the target environment.
            component(canonicalize_name(req.name), versions[0].version, 'pypi')
    elif Path(name).name in ('package-lock.json', 'npm-shrinkwrap.json'):
        try:
            lock = json.loads(text)
            if not isinstance(lock, dict):
                raise ValueError()
            version = lock.get('lockfileVersion')
            if version in (2, 3):
                packages = lock.get('packages')
                if not isinstance(packages, dict):
                    raise ValueError()
                entries = [(p, v) for p, v in packages.items() if p]
            elif version == 1:
                entries = []
                pending = [lock.get('dependencies', {})]
                while pending:
                    group = pending.pop()
                    if not isinstance(group, dict):
                        raise ValueError()
                    for package, data in group.items():
                        entries.append((package, data))
                        if isinstance(data, dict) and 'dependencies' in data:
                            pending.append(data['dependencies'])
            else:
                stats['total'] = 1
                issue('unsupported', 0, 'Unsupported npm lockfile version')
                return components, stats
            for position, (location, data) in enumerate(entries, 1):
                stats['total'] += 1
                if not isinstance(data, dict):
                    issue('invalid', position, 'Invalid npm package record')
                    continue
                package = data.get('name') or location.split('node_modules/')[-1]
                version = data.get('version')
                if data.get('link') or not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
                    issue('unresolved', position, 'Link or unresolved npm version')
                elif not isinstance(package, str) or not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*', package):
                    issue('invalid', position, 'Invalid npm package name')
                else:
                    component(package, version, 'npm')
        except (ValueError, RecursionError):
            components.clear()
            stats.update(total=1, pinned=0, unresolved=0, invalid=0, unsupported=0, issues=[])
            issue('invalid', 0, 'Malformed npm lockfile; no inventory claimed')
    else:
        return None
    return components, stats
