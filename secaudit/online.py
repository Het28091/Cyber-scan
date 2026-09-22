"""Non-AI advisory lookups. Fixed HTTPS endpoint; never execute response content."""
import http.client,ipaddress,json,re,socket,time
from .security import Scope,PolicyError
from .network import request
from .models import Finding,now

ENDPOINT='https://api.osv.dev/v1/query'

def provider_scope():
    addresses={str(ipaddress.ip_address(r[4][0])) for r in socket.getaddrinfo('api.osv.dev',443,type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise PolicyError('advisory service must resolve to public IPs')
    return Scope({'authorization':'Operator selected internet mode with online_dependencies','origins':[ENDPOINT],'exclusions':[],'environment':'advisory-provider','profiles':['passive'],'max_requests':100,'max_seconds':300,'allowed_ips':sorted(addresses)})

def package_key(component):
    name=component.get('name');version=component.get('version');purl=component.get('purl','')
    ecosystem='PyPI' if purl.startswith('pkg:pypi/') else 'npm' if purl.startswith('pkg:npm/') else None
    if not ecosystem or not isinstance(name,str) or not isinstance(version,str):return None
    pattern=r'[A-Za-z0-9][A-Za-z0-9._-]{0,213}' if ecosystem=='PyPI' else r'(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]{0,213}'
    if not re.fullmatch(pattern,name) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}',version):return None
    if ecosystem=='PyPI': name=re.sub(r'[-_.]+','-',name).lower()
    return ecosystem,name,version

def parse_response(payload,key):
    if not isinstance(payload,dict) or not isinstance(payload.get('vulns',[]),list): raise PolicyError('invalid advisory response')
    findings=[];ecosystem,name,version=key
    for item in payload.get('vulns',[]):
        if not isinstance(item,dict) or not isinstance(item.get('id'),str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,120}',item['id']): raise PolicyError('invalid advisory ID')
        if item.get('withdrawn'):continue
        summary=item.get('summary') or 'Provider-reported affected package version; validate applicability.'
        if not isinstance(summary,str):raise PolicyError('invalid advisory summary')
        # No invented CVSS conversion. MEDIUM is a provisional triage priority, not a provider rating.
        finding=Finding('OSV-'+item['id'],'Package advisory: '+item['id'],f'pkg:{"pypi" if ecosystem=="PyPI" else "npm"}/{name}@{version}',summary[:2000],
            'Review the cited advisory and upgrade to a confirmed unaffected release; retest the application.',severity='MEDIUM',confidence='HIGH',scanner='osv-api',scanner_version='v1',
            evidence=['Advisory: https://osv.dev/vulnerability/'+item['id'],'Query: '+ecosystem+' '+name+' '+version,'MEDIUM is provisional triage priority; provider CVSS has not been evaluated.'],
            provenance=[{'provider':'OSV','queried_at':now(),'advisory_id':item['id']}])
        findings.append(finding)
    token=payload.get('next_page_token','')
    if not isinstance(token,str) or len(token)>4096:raise PolicyError('invalid advisory page token')
    return findings,token

def scan_dependencies(components,cfg):
    if cfg.mode!='internet' or cfg.ai.enabled:raise PolicyError('online lookups require non-AI internet mode')
    keys=[];unsupported=0
    for component in components:
        key=package_key(component)
        if key is None:unsupported+=1
        elif key not in keys:keys.append(key)
    selected=keys[:cfg.online_package_limit]
    usage={'provider':'OSV','endpoint':ENDPOINT,'started':now(),'disclosure':['package ecosystem','package name','package version'],
           'requests':0,'responses':0,'completed':0,'failed':0,'skipped':len(keys)-len(selected)+unsupported,'packages':len(keys)}
    findings=[];events=[]
    if not selected:return findings,usage,['No supported pinned package versions available for online advisory lookup.']
    try:scope=provider_scope()
    except (ValueError,OSError):
        usage['failed']=len(selected);return findings,usage,['OSV unavailable: DNS or public-address policy failed. No clean dependency result claimed.']
    started=time.monotonic()
    for key in selected:
        if time.monotonic()-started>=min(cfg.timeout,60):usage['skipped']+=1;continue
        ecosystem,name,version=key
        payload=json.dumps({'package':{'ecosystem':ecosystem,'name':name},'version':version}).encode()
        usage['requests']+=1
        try:
            status,_,raw=request(ENDPOINT,scope,method='POST',body=payload,headers={'Content-Type':'application/json','User-Agent':'Secaudit/0.4 non-AI-advisory-client'},timeout=8,max_bytes=1_000_000)
            if status!=200:raise PolicyError('advisory service HTTP failure')
            fs,next_page=parse_response(json.loads(raw),key);findings+=fs;usage['responses']+=1
            if next_page:usage['skipped']+=1;events.append('OSV response paginated: additional results not fetched; coverage remains incomplete.')
            else:usage['completed']+=1
        except (ValueError,OSError,KeyError,TypeError,http.client.HTTPException):
            usage['failed']+=1;events.append('OSV query failed or returned invalid output. No clean dependency result claimed.')
    if usage['skipped']:events.append('Online advisory coverage incomplete: request/time budget, unsupported inventory or pagination.')
    usage['finished']=now()
    return findings,usage,events
