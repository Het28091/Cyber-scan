"""Small deterministic parser corpus; no runtime exploitability claims or traffic."""
import json
from pathlib import Path
from unittest.mock import patch
from secaudit.config import Config
from secaudit.scanners import source_scan
from secaudit.frameworks import apply_mappings


def cases():
    pairs=[
        ('PY-DYNAMIC-EXEC','a.py','eval(value)','str(value)'),
        ('PY-SHELL','a.py','subprocess.run(value, shell=True)','subprocess.run([value], shell=False)'),
        ('PY-PICKLE','a.py','pickle.loads(value)','json.loads(value)'),
        ('PY-SQL-DYNAMIC','a.py','cursor.execute(f"SELECT {value}")','cursor.execute("SELECT ?", (value,))'),
        ('PY-YAML-LOAD','a.py','yaml.load(value, Loader=yaml.UnsafeLoader)','yaml.safe_load(value)'),
        ('SECRET-LITERAL','a.env','token="synthetic-canary-value"','token=os.environ.get("TOKEN")'),
        ('CONFIG-DEBUG','a.cfg','debug=true','debug=false'),
        ('CONFIG-TLS','a.py','requests.get(url, verify=False)','requests.get(url, verify=True)'),
        ('DOCKER-USER','Dockerfile','FROM fixture\nUSER root','FROM fixture\nUSER 1001')]
    for rule,name,positive,clean in pairs:
        yield rule+'-positive',name,positive,{rule}
        yield rule+'-clean',name,clean,set()
    spec={'openapi':'3.0.3','paths':{'/owned':{'get':{}}},'servers':[{'url':'http://fixture.invalid'}],
        'components':{'securitySchemes':{'query':{'type':'apiKey','in':'query'},'oauth':{'type':'oauth2','flows':{'implicit':{}}}}}}
    yield 'api-positive','api.json',json.dumps(spec),{'API-SECURITY','API-CLEARTEXT-SERVER','API-QUERY-CREDENTIAL','API-OAUTH-FLOW'}
    spec['security']=[{'missing':[]}];spec['servers']=[];spec['components']={}
    yield 'api-reference','api.json',json.dumps(spec),{'API-SECURITY-REFERENCE'}
    spec['components']={'securitySchemes':{'missing':{'type':'http','scheme':'bearer'}}}
    yield 'api-clean','api.json',json.dumps(spec),set()
    pod={'apiVersion':'v1','kind':'Pod','spec':{'hostNetwork':True,'automountServiceAccountToken':True,
        'volumes':[{'hostPath':{'path':'/fixture'}}],'containers':[{'securityContext':{
            'privileged':True,'allowPrivilegeEscalation':True,'runAsUser':0,'capabilities':{'add':['SYS_ADMIN']}}}]}}
    yield 'kubernetes-positive','pod.json',json.dumps(pod),{'K8S-HOST-NAMESPACE','K8S-TOKEN-MOUNT','K8S-HOST-PATH','K8S-PRIVILEGED','K8S-ESCALATION','K8S-ROOT','K8S-CAPABILITIES'}
    pod['spec']={'hostNetwork':False,'automountServiceAccountToken':False,'containers':[{'securityContext':{'privileged':False,'allowPrivilegeEscalation':False,'runAsUser':1001,'capabilities':{'drop':['ALL']}}}]}
    yield 'kubernetes-clean','pod.json',json.dumps(pod),set()


def evaluate():
    rows=[];tp=fp=fn=0;clean=0;rules=set();mappings={}
    for ident,name,content,expected in cases():
        # Exercise production AST/regex/declaration logic; explicitly isolate only traversal.
        with patch('secaudit.scanners.files',return_value=iter([(name,content)])):
            findings,_,_,_=source_scan('.',Config(),lambda *a:None)
        actual={f.rule for f in findings};rules|=expected
        tp+=len(actual&expected);fp+=len(actual-expected);fn+=len(expected-actual)
        if not expected and not actual:clean+=1
        rows.append({'case':ident,'expected':sorted(expected),'observed':sorted(actual),
            'false_positive_rules':sorted(actual-expected),'false_negative_rules':sorted(expected-actual)})
        run={'findings':[f.to_dict() for f in findings]};apply_mappings(run)
        for finding in run['findings']:mappings[finding['rule']]=finding['mappings']
    return {'schema':1,'status':'PASS' if not fp and not fn else 'FAIL','cases':rows,
        'tp':tp,'fp':fp,'fn':fn,'clean_cases_passed':clean,'covered_builtin_rules':sorted(rules),'mappings':mappings,
        'limitations':['Curated syntax/declaration samples only; not a representative vulnerability prevalence dataset',
            'Filesystem traversal is supplied by a fixture; no application code is executed',
            'Not runtime authorization, exploitability, full parser/schema, installed inventory or compliance validation',
            'Dependency inventory/advisory parsers and external adapters use separate existing unit/live controls; not included in these counts']}


if __name__=='__main__':
    result=evaluate();path=Path('artifacts/checkpoints/independent/detection-quality.json')
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','tp','fp','fn','clean_cases_passed','covered_builtin_rules')}))
    raise SystemExit(result['status']!='PASS')
