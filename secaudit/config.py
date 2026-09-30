from dataclasses import dataclass, field, fields
from pathlib import Path
import json,os,re
from .security import PolicyError

@dataclass
class AIConfig:
    enabled: bool=False
    provider: str='none'
    endpoint: str=''
    model: str=''
    api_key_env: str='SECAUDIT_API_KEY'
    timeout: int=15
    retry_limit: int=0
    context_tokens: int=4096
    output_tokens: int=512
    concurrency: int=1
    request_budget: int=2
    token_budget: int=8192
    cost_ceiling: float=0.0
    input_price_per_million: float=0.0
    output_price_per_million: float=0.0
    permitted_data_categories: list=field(default_factory=lambda:['finding_metadata'])
    redaction: bool=True
    failure_policy: str='continue'
    approved_ips: list=field(default_factory=list)

@dataclass
class Config:
    mode: str='offline'
    source: str=''
    target: str=''
    scope: str='scope.json'
    output: str='runs'
    modules: list=field(default_factory=lambda:['source','secrets','config','dependencies','openapi'])
    strict: bool=False
    advisory_dataset: str=''
    dataset_max_age_days: int=30
    block_stale_data: bool=False
    scanners: dict=field(default_factory=dict)
    target_workflow: dict=field(default_factory=dict)
    online_package_limit: int=25
    pdf_required: bool=False
    max_files: int=5000
    max_file_bytes: int=1_000_000
    max_total_bytes: int=50_000_000
    timeout: int=60
    ai: AIConfig=field(default_factory=AIConfig)
    def validate(self):
        for key in ('source','target','scope','output','advisory_dataset'):
            if not isinstance(getattr(self,key),str): raise PolicyError('paths and target must be strings')
        if self.mode in ('local-ai','connected-ai') and os.environ.get('SECAUDIT_EXPERIMENTAL_AI')!='1': raise PolicyError('AI is experimental; explicit SECAUDIT_EXPERIMENTAL_AI=1 opt-in required')
        if self.mode not in ('offline','internet','local-ai','connected-ai'): raise PolicyError('invalid mode')
        if type(self.strict) is not bool or type(self.ai.enabled) is not bool: raise PolicyError('booleans required')
        if not isinstance(self.modules,list) or not all(isinstance(x,str) for x in self.modules): raise PolicyError('modules must be a list')
        if not self.modules: raise PolicyError('select at least one module')
        if len(set(self.modules))!=len(self.modules): raise PolicyError('duplicate modules')
        if set(self.modules)-{'source','secrets','config','dependencies','openapi','web','target_workflow','gitleaks','semgrep','trivy','syft','online_dependencies'}: raise PolicyError('unknown module')
        from .target_workflow import validate
        validate(self.target_workflow)
        if self.target_workflow and ('target_workflow' not in self.modules or not self.target or 'web' in self.modules): raise PolicyError('target workflow requires a target and its own module, without a parallel web crawl')
        if 'target_workflow' in self.modules and not self.target_workflow: raise PolicyError('target workflow plan required')
        for key,upper in [('max_files',50000),('max_file_bytes',10_000_000),('max_total_bytes',500_000_000),('timeout',300)]:
            if type(getattr(self,key)) is not int or not 1<=getattr(self,key)<=upper: raise PolicyError(f'invalid {key}')
        if type(self.dataset_max_age_days) is not int or not 0<=self.dataset_max_age_days<=36500: raise PolicyError('invalid dataset freshness window')
        if type(self.block_stale_data) is not bool or type(self.pdf_required) is not bool: raise PolicyError('invalid policy boolean')
        if not isinstance(self.scanners,dict) or set(self.scanners)-{'gitleaks','semgrep','trivy','syft'}: raise PolicyError('invalid scanner configuration')
        for options in self.scanners.values():
            if not isinstance(options,dict) or set(options)-{'executable','rules','cache'} or not all(isinstance(v,str) for v in options.values()): raise PolicyError('invalid scanner options')
        a=self.ai
        for key in ('provider','endpoint','model','api_key_env','failure_policy'):
            if not isinstance(getattr(a,key),str): raise PolicyError('AI text fields must be strings')
        if not isinstance(a.approved_ips,list) or not all(isinstance(x,str) for x in a.approved_ips): raise PolicyError('AI pins must be a list of strings')
        if self.mode in ('offline','internet') and a.enabled: raise PolicyError('AI is forbidden in non-AI modes')
        if self.mode in ('local-ai','connected-ai') and not a.enabled: raise PolicyError('AI modes require an enabled provider')
        if not re.fullmatch(r'SECAUDIT_[A-Z0-9_]{1,80}',a.api_key_env): raise PolicyError('AI credential must reference a SECAUDIT_ environment variable')
        if 'online_dependencies' in self.modules and self.mode!='internet': raise PolicyError('online dependencies require internet mode')
        if type(self.online_package_limit) is not int or not 1<=self.online_package_limit<=100: raise PolicyError('online package limit must be 1..100')
        if a.enabled and ((self.mode=='local-ai' and a.provider!='ollama') or (self.mode=='connected-ai' and a.provider!='openai-compatible')): raise PolicyError('provider does not match mode')
        if a.enabled and (not a.model or not a.endpoint or not a.approved_ips): raise PolicyError('AI endpoint, model and pinned IPs required')
        if a.enabled:
            import ipaddress
            from urllib.parse import urlsplit
            from .security import canonical
            canonical(a.endpoint)
            if urlsplit(a.endpoint).query: raise PolicyError('AI endpoint cannot contain a query')
            pins=[ipaddress.ip_address(x) for x in a.approved_ips]
            if self.mode=='local-ai' and any(not x.is_loopback for x in pins): raise PolicyError('local AI must be loopback')
            if self.mode=='connected-ai' and not a.endpoint.startswith('https://'): raise PolicyError('API AI requires HTTPS')
        for key in ('timeout','context_tokens','output_tokens','request_budget','token_budget'):
            if type(getattr(a,key)) is not int or not 1<=getattr(a,key)<=1_000_000: raise PolicyError(f'invalid AI {key}')
        if type(a.retry_limit) is not int or type(a.concurrency) is not int or a.retry_limit!=0 or a.concurrency!=1: raise PolicyError('this version supports retry_limit=0 and concurrency=1')
        if a.timeout>120 or a.output_tokens>=a.context_tokens: raise PolicyError('AI timeout must be at most 120 seconds and output must fit context')
        if a.failure_policy not in ('continue','required') or a.permitted_data_categories!=['finding_metadata'] or a.redaction is not True: raise PolicyError('unsupported AI disclosure or failure policy')
        for key in ('cost_ceiling','input_price_per_million','output_price_per_million'):
            v=getattr(a,key)
            if type(v) not in (int,float) or not 0<=v<1e9: raise PolicyError(f'invalid {key}')
        if a.cost_ceiling and not (a.input_price_per_million and a.output_price_per_million): raise PolicyError('cost ceiling requires prices')
        return self

def load(path=None):
    data=json.loads(Path(path).read_text()) if path else {}
    if not isinstance(data,dict): raise PolicyError('configuration must be an object')
    if set(data)-{x.name for x in fields(Config)}: raise PolicyError('unknown configuration fields')
    ad=data.pop('ai',{})
    if not isinstance(ad,dict) or set(ad)-{x.name for x in fields(AIConfig)}: raise PolicyError('unknown AI fields')
    return Config(**data,ai=AIConfig(**ad)).validate()
