"""Reusable local assessment inputs; saving never authorizes or starts a scan."""
import json
import re
import sqlite3
import uuid
from pathlib import Path
from dataclasses import fields
from .config import Config,AIConfig
from .models import now
from .security import PolicyError,Scope,canonical


def validate_configuration(data):
    allowed={'source','target','preset','scope','scanners','target_workflow','ai','modules','assessment_options'}
    if not isinstance(data,dict) or set(data)-allowed:raise PolicyError('unsupported saved configuration fields')
    if len(json.dumps(data).encode())>100000:raise PolicyError('configuration exceeds 100 KB')
    source=data.get('source','');target=data.get('target','');mode=data.get('preset','internet')
    if not isinstance(source,str) or not isinstance(target,str):raise PolicyError('source and target must be strings')
    if not source and not target:raise PolicyError('a source directory or target is required; ZIP files are not saved')
    ai=data.get('ai',{})
    if not isinstance(ai,dict) or set(ai)-{f.name for f in fields(AIConfig)}:raise PolicyError('invalid provider configuration')
    cfg=Config(mode=mode,source=source,target=target,scanners=data.get('scanners',{}),target_workflow=data.get('target_workflow',{}),ai=AIConfig(**ai))
    if not isinstance(cfg.scanners,dict):raise PolicyError('invalid scanner configuration')
    cfg.modules+=list(cfg.scanners)
    if target:cfg.modules.append('target_workflow' if cfg.target_workflow else 'web')
    from .dashboard_config import assessment_options
    assessment_options(cfg,data)
    if mode in ('offline','internet') and 'ai' in data:raise PolicyError('AI configuration is forbidden in non-AI modes')
    if target:
        canonical(target)
        scope=Scope(data.get('scope'),allow_public=mode in ('internet','connected-ai'))
        if cfg.target_workflow and (scope.data['profiles']!=['passive','bounded'] or scope.auth):
            raise PolicyError('workflow requires bounded scope and its own account credentials')
    elif 'scope' in data:raise PolicyError('scope requires a target')
    return json.loads(json.dumps(data))


def preview(data):
    config=validate_configuration(data)
    workflow=config.get('target_workflow',{});scope=config.get('scope',{});ai=config.get('ai',{})
    operations=len(workflow.get('roles',[]))+len(workflow.get('cors',[]))+len(workflow.get('browser',{}).get('urls',[]))+(4 if workflow.get('login') else 0)
    return {'configuration':config,'summary':{
        'mode':config.get('preset','internet'),'source':config.get('source',''),'target':config.get('target',''),
        'authorized_prefixes':scope.get('origins',[]),'excluded_prefixes':scope.get('exclusions',[]),
        'target_ip_pins':scope.get('allowed_ips',[]),'request_limit':scope.get('max_requests'),
        'time_limit_seconds':scope.get('max_seconds'),'workflow_requests':operations,
        'workflow_operations':list(workflow),'scanners':list(config.get('scanners',{})),
        'selected_source_modules':config.get('modules','Preset defaults'),
        'assessment_options':config.get('assessment_options',{}),
        'provider':ai.get('provider','none'),'model':ai.get('model',''),
        'provider_endpoint':ai.get('endpoint',''),'provider_ip_pins':ai.get('approved_ips',[]),
        'ai_request_budget':ai.get('request_budget',2) if ai else 0,
        'ai_token_budget':ai.get('token_budget',8192) if ai else 0,
        'network_disclosure':('OSV package-identifier disclosure selected. ' if 'online_dependencies' in config.get('modules',(['online_dependencies'] if config.get('preset','internet')=='internet' else [])) else 'OSV lookups not selected. ')+'Enabled AI receives finding IDs, rules and severities only.',
        'limitation':'Configuration review only. No DNS, credentials, source paths, tools, provider readiness or target access have been checked. Saved pins and authorization must be reviewed before each run.'}}


class Profiles:
    def __init__(self,root):
        path=Path(root)/'profiles.sqlite3'
        if path.is_symlink():raise PolicyError('symlink profile database refused')
        self.db=sqlite3.connect(path,timeout=10);path.chmod(0o600)
        with self.db:self.db.execute('CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,name TEXT NOT NULL,updated TEXT NOT NULL,config TEXT NOT NULL)')

    def close(self):self.db.close()

    def list(self):
        return [{'id':ident,'revision':revision,'name':name,'updated_at':updated,'configuration':json.loads(config)} for ident,revision,name,updated,config in self.db.execute('SELECT * FROM profiles ORDER BY updated DESC LIMIT 100')]

    def save(self,data):
        if not isinstance(data,dict) or set(data)-{'id','revision','name','configuration'}:raise PolicyError('invalid profile fields')
        ident=data.get('id','');revision=data.get('revision',0);name=data.get('name','')
        if ident and (not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident)):raise PolicyError('invalid profile ID')
        if type(revision) is not int or revision<0:raise PolicyError('invalid profile revision')
        if not isinstance(name,str) or not 1<=len(name.strip())<=100 or any(ord(c)<32 for c in name):raise PolicyError('profile name must contain 1–100 printable characters')
        config=validate_configuration(data.get('configuration'))
        try:
            self.db.execute('BEGIN IMMEDIATE')
            if ident:
                row=self.db.execute('SELECT revision FROM profiles WHERE id=?',(ident,)).fetchone()
                if not row or row[0]!=revision:raise PolicyError('profile changed; reload before saving')
            else:
                if revision!=0:raise PolicyError('new profiles start at revision zero')
                if self.db.execute('SELECT COUNT(*) FROM profiles').fetchone()[0]>=100:raise PolicyError('profile limit reached')
                ident=uuid.uuid4().hex
            updated=now()
            self.db.execute('INSERT OR REPLACE INTO profiles VALUES(?,?,?,?,?)',(ident,revision+1,name.strip(),updated,json.dumps(config)))
            self.db.commit()
        except BaseException:self.db.rollback();raise
        return {'id':ident,'revision':revision+1,'name':name.strip(),'updated_at':updated,'configuration':config}

    def delete(self,ident,revision):
        if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident) or type(revision) is not int:raise PolicyError('invalid profile deletion')
        with self.db:
            result=self.db.execute('DELETE FROM profiles WHERE id=? AND revision=?',(ident,revision))
            if result.rowcount!=1:raise PolicyError('profile changed; reload before deleting')
        return {'deleted':ident}
