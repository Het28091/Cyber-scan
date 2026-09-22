"""Static credentials, restricted to one origin and explicit path prefixes."""
import ipaddress
import os
import re
from urllib.parse import urlsplit
from .security import PolicyError, canonical, register_secret


class StaticAuth:
    def __init__(self, data):
        if not isinstance(data, dict) or set(data) != {'type', 'env', 'origin', 'paths'}:
            raise PolicyError('authentication requires type, env, origin and paths only')
        if data['type'] not in ('bearer', 'cookie'):
            raise PolicyError('unsupported authentication type')
        if not isinstance(data['env'], str) or not re.fullmatch(r'SECAUDIT_TARGET_[A-Z0-9_]{1,80}', data['env']):
            raise PolicyError('authentication must reference a SECAUDIT_TARGET_ environment variable')
        origin, path, host, _ = canonical(data['origin'])
        if path != '/' or urlsplit(data['origin']).query:
            raise PolicyError('authentication origin must not contain a path or query')
        if not origin.startswith('https:'):
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise PolicyError('credentials require HTTPS except IP-literal loopback labs')
        if not isinstance(data['paths'], list) or not 1 <= len(data['paths']) <= 50:
            raise PolicyError('authentication requires bounded path prefixes')
        self.paths = []
        for item in data['paths']:
            if not isinstance(item, str) or not item.startswith('/'):
                raise PolicyError('authentication paths must be absolute paths')
            _, normalized, _, _ = canonical(origin + item)
            if urlsplit(origin + item).query:
                raise PolicyError('authentication paths cannot include queries')
            self.paths.append(normalized)
        self.origin, self.kind, self.env = origin, data['type'], data['env']

    def matches(self, url):
        origin, path, _, _ = canonical(url)
        return origin == self.origin and any(p == '/' or path == p or path.startswith(p.rstrip('/') + '/') for p in self.paths)

    def headers(self, url):
        if not self.matches(url):
            return {}
        value = os.environ.get(self.env, '')
        if not 8 <= len(value) <= 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise PolicyError('authentication credential missing or invalid; no request sent')
        if self.kind == 'bearer':
            if not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', value):
                raise PolicyError('invalid bearer credential')
            register_secret(value)
            return {'Authorization': 'Bearer ' + value}
        # Deliberately accepts only ordinary unquoted session cookie pairs.
        values = []
        for pair in value.split(';'):
            match = re.fullmatch(r'\s*([!#$%&\x27*+.^_`|~0-9A-Za-z-]+)=([\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]{8,})\s*', pair)
            if not match:
                raise PolicyError('invalid cookie pairs; each session value must contain at least eight characters')
            values.append(match[2])
        register_secret(value)
        for secret in values:
            register_secret(secret)
        return {'Cookie': value}
