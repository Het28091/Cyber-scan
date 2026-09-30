"""Validate dashboard configuration before persisting or starting a job."""
import os
from dataclasses import fields
from .config import AIConfig
from .security import PolicyError


def presets():
    return ['internet','offline'] + (['local-ai','connected-ai'] if os.environ.get('SECAUDIT_EXPERIMENTAL_AI')=='1' else [])


def assessment_options(cfg,data):
    """Apply explicit source modules after target/scanner modules are established."""
    builtins={'source','secrets','config','dependencies','openapi','online_dependencies'}
    if 'modules' in data:
        modules=data['modules']
        if not isinstance(modules,list) or not all(isinstance(m,str) for m in modules) or len(set(modules))!=len(modules) or set(modules)-builtins:
            raise PolicyError('select supported source modules without duplicates')
        cfg.modules=[m for m in cfg.modules if m not in builtins]+modules
    options=data.get('assessment_options',{})
    allowed={'max_files','max_file_bytes','max_total_bytes','timeout','strict','pdf_required','advisory_dataset','dataset_max_age_days','block_stale_data','online_package_limit'}
    if not isinstance(options,dict) or set(options)-allowed:raise PolicyError('invalid assessment options')
    for key,value in options.items():setattr(cfg,key,value)
    return cfg.validate()


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
