"""Explicit dashboard preparation; no target HTTP or provider inference calls."""
import ipaddress
import json
import os
from dataclasses import asdict
from pathlib import Path
import socket
import stat
from urllib.parse import urlsplit
from .config import AIConfig, Config
from .security import Scope, canonical, PolicyError


def website_scope(payload):
    if set(payload) != {'target', 'authorization'}:
        raise PolicyError('Target URL and authorization reference required')
    target = payload['target']
    if not isinstance(target, str) or len(target) > 2048:
        raise PolicyError('Target URL must be at most 2048 characters')
    _, _, host, port = canonical(target)
    if urlsplit(target).query:
        raise PolicyError('Use a URL without query parameters for scope preparation')
    authorization = payload['authorization']
    if not isinstance(authorization, str) or not 5 <= len(authorization.strip()) <= 500:
        raise PolicyError('Enter an authorization reference of 5 to 500 characters')
    # Only this hostname is resolved; no HTTP requests or redirect expansion.
    addresses = sorted({str(ipaddress.ip_address(row[4][0]))
                        for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    data = dict(authorization=authorization.strip(), origins=[target], exclusions=[],
                environment='operator-authorized', profiles=['passive'],
                max_requests=10, max_seconds=30, allowed_ips=addresses)
    Scope(data)
    return {'scope': data, 'notice': 'Review the URL prefix, IP pins and excluded routes before starting. DNS resolution does not prove ownership.'}


def prepared_ai(payload):
    if payload:
        raise PolicyError('Server AI configuration takes no browser-supplied path or credential')
    if os.environ.get('SECAUDIT_EXPERIMENTAL_AI') != '1':
        raise PolicyError('Restart the dashboard with --experimental-ai to enable AI')
    path = os.environ.get('SECAUDIT_AI_CONFIG', '')
    if not path:
        raise PolicyError('Set SECAUDIT_AI_CONFIG to a reviewed configuration file before starting the dashboard')
    try:
        fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ValueError()
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        data = json.loads(raw)
        cfg = Config(mode=data['mode'], ai=AIConfig(**data['ai'])).validate()
        if cfg.mode not in ('local-ai', 'connected-ai'):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError):
        raise PolicyError('Prepared AI configuration is invalid or unreadable; check it on the server') from None
    present = bool(os.environ.get(cfg.ai.api_key_env)) if cfg.mode == 'connected-ai' else None
    return {'mode': cfg.mode, 'ai': asdict(cfg.ai), 'credential_present': present,
            'status': 'CONFIGURED_NOT_TESTED' if present is not False else 'CREDENTIAL_MISSING',
            'notice': 'Settings loaded only. Review provider, model, budgets and disclosure. Readiness runs when you start; free-only billing must be configured with your provider.'}
