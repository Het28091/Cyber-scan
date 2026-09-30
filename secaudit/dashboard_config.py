"""Validate dashboard configuration before persisting or starting a job."""
import os
from dataclasses import fields
from .config import AIConfig
from .security import PolicyError


def presets():
    return ['internet','offline'] + (['local-ai','connected-ai'] if os.environ.get('SECAUDIT_EXPERIMENTAL_AI')=='1' else [])


def configure(cfg,data):
    ai=data.get('ai')
    if cfg.mode in ('local-ai','connected-ai'):
        if data.get('ai_disclosure_accepted') is not True:
            raise PolicyError('Accept finding-metadata disclosure to the configured provider')
        if not isinstance(ai,dict) or set(ai)-{f.name for f in fields(AIConfig)}:
            raise PolicyError('invalid AI configuration; credentials must remain environment references')
        cfg.ai=AIConfig(**ai)
    elif ai is not None or data.get('ai_disclosure_accepted'):
        raise PolicyError('AI configuration is forbidden in non-AI modes')
    scanners=data.get('scanners',{})
    if not isinstance(scanners,dict): raise PolicyError('scanner configuration must be an object')
    cfg.scanners=scanners
    cfg.modules=list(dict.fromkeys(cfg.modules+list(scanners)))
    return cfg.validate()
