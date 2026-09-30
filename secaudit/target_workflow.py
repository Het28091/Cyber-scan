"""Explicit, bounded test-account workflows. No crawling or redirect following."""
import json
import math
import os
import re
import time
from urllib.parse import urlsplit
from .auth import StaticAuth
from .models import Finding
from .network import request
from .security import PolicyError, canonical, register_secret


def validate(plan):
    if not isinstance(plan,dict) or set(plan)-{'login','roles','cors','browser'}:
        raise PolicyError('unsupported target workflow fields')
    if not plan: return
    if not any(plan.get(k) for k in ('login','roles','cors','browser')): raise PolicyError('empty target workflow')
    login=plan.get('login')
    if login is not None:
        if not isinstance(login,dict) or set(login)!={'url','credentials_env','token_field','verify_url','logout_url'}:
            raise PolicyError('login requires explicit login, verification and logout URLs, credentials environment and token field')
        if not isinstance(login['credentials_env'],str) or not re.fullmatch(r'SECAUDIT_TARGET_[A-Z0-9_]{1,80}',login['credentials_env']): raise PolicyError('login credentials require a target environment reference')
        if not isinstance(login['token_field'],str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',login['token_field']): raise PolicyError('invalid token field')
        origins=[]
        for key in ('url','verify_url','logout_url'):
            origin,path,host,port=canonical(login[key]);origins.append(origin)
            # Reuse the transport-security rules for static credentials.
            StaticAuth({'type':'bearer','env':login['credentials_env'],'origin':origin,'paths':[path]})
            if urlsplit(login[key]).query: raise PolicyError('workflow URLs cannot contain queries')
        if len(set(origins))!=1 or len({login[k] for k in ('url','verify_url','logout_url')})!=3: raise PolicyError('login URLs must be distinct and share one origin')
    roles=plan.get('roles',[])
    if not isinstance(roles,list) or len(roles)>10: raise PolicyError('at most ten role probes supported')
    for role in roles:
        required={'name','url','authentication','expected_status'}
        if not isinstance(role,dict) or not required<=set(role) or set(role)-(required|{'response_assertions'}): raise PolicyError('invalid role probe')
        if not isinstance(role['name'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',role['name']): raise PolicyError('invalid role name')
        if type(role['expected_status']) is not int or role['expected_status'] not in (200,401,403,404): raise PolicyError('invalid expected role status')
        canonical(role['url'])
        if urlsplit(role['url']).query: raise PolicyError('workflow URLs cannot contain queries')
        auth=StaticAuth(role['authentication'])
        if not auth.matches(role['url']): raise PolicyError('role URL is outside credential scope')
        assertions=role.get('response_assertions',[])
        if not isinstance(assertions,list) or len(assertions)>10:raise PolicyError('at most ten role response assertions supported')
        for assertion in assertions:
            if not isinstance(assertion,dict) or set(assertion)!={'path','equals_env'}:raise PolicyError('invalid response assertion')
            path=assertion['path'];env=assertion['equals_env']
            if not isinstance(path,list) or not 1<=len(path)<=12 or any(not (isinstance(p,str) and 1<=len(p)<=128 or type(p) is int and 0<=p<=1000) for p in path):raise PolicyError('invalid response field path')
            if not isinstance(env,str) or not re.fullmatch(r'SECAUDIT_TARGET_[A-Z0-9_]{1,80}',env):raise PolicyError('expected response values require target environment references')
    cors=plan.get('cors',[])
    if not isinstance(cors,list) or len(cors)>10: raise PolicyError('at most ten CORS probes supported')
    for url in cors:
        canonical(url)
        if urlsplit(url).query: raise PolicyError('workflow URLs cannot contain queries')
    browser=plan.get('browser')
    if browser is not None:
        if not isinstance(browser,dict) or set(browser)-{'urls','executable'} or not isinstance(browser.get('urls'),list) or not 1<=len(browser['urls'])<=5 or not isinstance(browser.get('executable',''),str): raise PolicyError('browser requires one to five explicit URLs and an optional executable')
        for url in browser['urls']:
            canonical(url)
            if urlsplit(url).query: raise PolicyError('workflow URLs cannot contain queries')


def prepare(plan,scope):
    validate(plan)
    if scope.data['profiles']!=['passive','bounded']: raise PolicyError('target workflow requires explicit passive + bounded scope profiles')
    if scope.auth: raise PolicyError('workflow uses its own scoped test accounts; remove static scope authentication')
    urls=list(plan.get('cors',[]))+[r['url'] for r in plan.get('roles',[])]+plan.get('browser',{}).get('urls',[])
    if plan.get('login'): urls += [plan['login'][k] for k in ('url','verify_url','logout_url')]
    required=len(plan.get('roles',[]))+len(plan.get('cors',[]))+len(plan.get('browser',{}).get('urls',[]))+(4 if plan.get('login') else 0)
    if required>scope.data['max_requests']: raise PolicyError('scope request budget cannot cover workflow and session invalidation verification')
    for url in urls: scope.check(url)


def expected_values(assertions):
    values=[]
    for assertion in assertions:
        raw=os.environ.get(assertion['equals_env'],'')
        if not raw or len(raw)>8192:raise PolicyError('response expectation missing or oversized')
        try:value=json.loads(raw)
        except (ValueError,RecursionError):raise PolicyError('response expectation must be a JSON scalar') from None
        if isinstance(value,(list,dict)) or isinstance(value,float) and not math.isfinite(value):raise PolicyError('response expectation must be a finite JSON scalar')
        values.append(value)
    return values


def compare_response(raw,assertions,expected):
    """Return booleans only: response and expected values never enter evidence."""
    try:document=json.loads(raw)
    except (ValueError,UnicodeError,RecursionError):raise PolicyError('role response is not valid JSON') from None
    matches=[]
    for assertion,wanted in zip(assertions,expected):
        value=document
        try:
            for part in assertion['path']:
                if isinstance(part,str) and isinstance(value,dict):value=value[part]
                elif type(part) is int and isinstance(value,list):value=value[part]
                else:raise KeyError()
            matches.append(type(value) is type(wanted) and value==wanted)
        except (KeyError,IndexError):matches.append(False)
    return matches


def execute(plan,scope,checkpoint):
    prepare(plan,scope)
    start=time.monotonic();used=0;findings=[];assets=[];events=[];complete=True;login_attempted=False
    def send(url,method='GET',body=None,headers=None):
        nonlocal used
        remaining=scope.data['max_seconds']-(time.monotonic()-start)
        if used>=scope.data['max_requests'] or remaining<=0: raise PolicyError('target workflow budget exhausted')
        used+=1
        result=request(url,scope,method,body,headers,timeout=min(5,remaining),max_bytes=65536)
        assets.append({'asset':url,'status':result[0],'method':method,'type':'target-workflow'})
        checkpoint(findings,assets)
        if result[0]>=500: raise PolicyError('target workflow stopped after server error')
        return result
    try:
        login=plan.get('login')
        if login:
            raw=os.environ.get(login['credentials_env'],'')
            if not raw or len(raw)>8192: raise PolicyError('login credentials missing or oversized')
            try: credentials=json.loads(raw)
            except ValueError: raise PolicyError('login credentials must be a JSON object') from None
            if not isinstance(credentials,dict) or not credentials or len(credentials)>10 or any(not isinstance(v,str) or not 8<=len(v)<=4096 for v in credentials.values()): raise PolicyError('login credential fields must be strings of 8..4096 characters')
            register_secret(raw)
            for value in credentials.values(): register_secret(value)
            login_attempted=True
            status,_,body=send(login['url'],'POST',json.dumps(credentials).encode(),{'Content-Type':'application/json'})
            if status in (401,403): login_attempted=False
            if status!=200: raise PolicyError('login rejected; no session established')
            try: token=json.loads(body)[login['token_field']]
            except (ValueError,KeyError,TypeError): raise PolicyError('login response lacks configured bearer token') from None
            if not isinstance(token,str) or not 8<=len(token)<=8192 or not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*',token): raise PolicyError('invalid session bearer token')
            register_secret(token)
            headers={'Authorization':'Bearer '+token}
            try:
                status,_,_=send(login['verify_url'],headers=headers)
                if status!=200: raise PolicyError('session rejected or expired before verification')
                events.append('SESSION_VERIFIED: test-account protected endpoint returned 200.')
            finally:
                # No retries or redirects; a failed cleanup is explicitly reported.
                try:
                    status,_,_=send(login['logout_url'],'POST',b'',headers)
                    if status not in (200,204): raise PolicyError('session logout rejected')
                    status,_,_=send(login['verify_url'],headers=headers)
                    if status not in (401,403): raise PolicyError('session remains usable or invalidation could not be verified')
                    events.append('SESSION_INVALIDATED: the former credential was rejected after logout.')
                except Exception:
                    events.append('SESSION_CLEANUP_UNVERIFIED: revoke the dedicated test session manually.')
                    raise
                finally: headers.clear()
        for role in plan.get('roles',[]):
            auth=StaticAuth(role['authentication'])
            assertions=role.get('response_assertions',[]);expected_fields=expected_values(assertions)
            status,_,body=send(role['url'],headers=auth.headers(role['url']))
            assets[-1]['role']=role['name']
            expected=role['expected_status']
            events.append(f"ROLE {role['name']}: expected {expected}, observed {status}; HTTP status comparison, no automatic authorization confirmation.")
            if status==401 and expected!=401:
                events.append('ROLE_NOT_TESTED: credential rejected or expired.');complete=False;continue
            if status!=expected:
                findings.append(Finding('ROLE-STATUS','Role access differs from declared expectation',role['url'],f'Expected HTTP {expected}; observed HTTP {status}.','Review the test account, route and authorization policy.',role=role['name'],evidence=[f'Expected {expected}; observed {status}'],confidence='LOW'))
            if assertions:
                if status!=expected:
                    events.append('ROLE_ASSERTIONS_NOT_TESTED: unexpected HTTP status.');complete=False
                else:
                    matches=compare_response(body,assertions,expected_fields)
                    assets[-1]['response_assertions']=[{'index':i+1,'matched':matched} for i,matched in enumerate(matches)]
                    for i,matched in enumerate(matches,1):
                        if not matched:findings.append(Finding('ROLE-RESPONSE','Role response differs from declared invariant',role['url'],f'Response assertion {i} did not match its configured expectation; values are omitted.','Review the test-account identity, expected data ownership and application authorization logic.',role=role['name'],evidence=[f'Assertion {i}: missing field, type difference or value mismatch.'],confidence='MEDIUM'))
                    events.append(f"ROLE {role['name']}: {sum(matches)}/{len(matches)} response assertions matched; values omitted.")
            checkpoint(findings,assets)
        for url in plan.get('cors',[]):
            status,headers,_=send(url,'OPTIONS',headers={'Origin':'https://secaudit-probe.invalid','Access-Control-Request-Method':'GET'})
            hd={k.lower():v for k,v in headers}
            if status in (200,204) and hd.get('access-control-allow-origin')=='https://secaudit-probe.invalid' and hd.get('access-control-allow-credentials','').lower()=='true':
                findings.append(Finding('CORS-CREDENTIALS','Credentialed CORS permits the probe origin',url,'Preflight reflects the synthetic origin and permits credentials.','Restrict credentialed CORS to reviewed origins; verify with an authorized browser.',evidence=['Synthetic Origin reflected; Access-Control-Allow-Credentials: true'],confidence='MEDIUM'))
            if status not in (200,204): events.append(f'CORS_NOT_TESTED: OPTIONS returned {status}.');complete=False
            checkpoint(findings,assets)
        for url in plan.get('browser',{}).get('urls',[]):
            status,headers,body=send(url)
            hd={k.lower():v for k,v in headers}
            if status!=200 or 'text/html' not in hd.get('content-type','').lower():
                events.append('BROWSER_NOT_TESTED: expected an HTML response with HTTP 200.');complete=False;continue
            from .target_browser import render
            remaining=scope.data['max_seconds']-(time.monotonic()-start)
            if remaining<=0: raise PolicyError('target browser time budget exhausted')
            inventory=render(body,plan['browser'].get('executable',''),min(15,remaining))
            assets[-1]['browser']=inventory
            events.append('BROWSER_SNAPSHOT: isolated static HTML rendered; JavaScript, navigation and browser network disabled.')
            checkpoint(findings,assets)
    except Exception as error:
        if login_attempted and not any(e.startswith(('SESSION_INVALIDATED','SESSION_CLEANUP_UNVERIFIED')) for e in events): events.append('SESSION_CLEANUP_UNVERIFIED: login outcome was uncertain; revoke any dedicated test session manually.')
        events.append(type(error).__name__+': target workflow incomplete; raw response discarded.')
        events.append(f'Workflow requests attempted: {used}.')
        return findings,assets,events,False
    events.append(f'Workflow requests attempted: {used}.')
    return findings,assets,events,complete
