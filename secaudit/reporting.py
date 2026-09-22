import csv,html,io,json
from pathlib import Path
from .security import atomic,write_json,csv_safe,redact

LIMITATIONS=['Findings require manual validation; no compliance certification or complete vulnerability detection.', 'Browser execution, state-changing active attacks, business-logic verification and authenticated role comparisons are not supported.', 'Dependency matching is limited by supplied snapshots and inventory coverage; missing data remains NOT TESTED.', 'Framework mappings are a reviewed subset of related evidence, not complete ASVS/NIST/ATT&CK control assessments.', 'Source rules are syntax/regex heuristics; external scanners require a working isolated execution profile.']

def export_csv(path,rows,keys):
    s=io.StringIO();w=csv.writer(s);w.writerow(keys)
    for row in rows: w.writerow([csv_safe(redact(row.get(k,''))) for k in keys])
    atomic(path,s.getvalue())

def reports(directory,run):
    d=Path(directory);run=redact(run)
    write_json(d/'run.json',run);write_json(d/'findings.json',run['findings']);write_json(d/'assets.json',run['assets'])
    write_json(d/'inventory.json',run.get('inventory_completeness',[]))
    export_csv(d/'findings.csv',run['findings'],['id','title','asset','line','severity','confidence','validation_status','remediation'])
    export_csv(d/'coverage.csv',run['coverage'],['module','status','reason'])
    mapping_rows=[dict(m,finding_id=f['id']) for f in run['findings'] for m in f.get('mappings',[])]
    export_csv(d/'framework-mappings.csv',mapping_rows,['finding_id','framework','version','control','rationale'])
    md=['# Secaudit technical assessment',f"Run: {run['id']}",f"Mode: {run['mode']} | State: {run['status']}",f"Findings: {len(run['findings'])}",'','## Limitations',*['- '+x for x in LIMITATIONS],'','## Coverage']
    md+=['- '+r['module']+': '+r['status']+' — '+r['reason'] for r in run['coverage']]
    md+=['','## Declaration inventory',json.dumps(run.get('inventory_completeness',[]))]
    for f in run['findings']:
        md += ['',f"## {f['title']}",f"{f['severity']} / {f['confidence']} / {f['validation_status']}",f"Location: {f['asset']}:{f['line']}",f['description'], 'Remediation: '+f['remediation'],'Retest: '+f['retest']]
    md+=['','## Network policy',json.dumps(run.get('network_policy',{})), '','## Online advisory usage',json.dumps(run.get('online_advisories',{})), '','## AI usage',json.dumps(run.get('ai_usage',{})), '','## Framework snapshot',json.dumps(run.get('framework_snapshot',{}))]
    md+=['','## Events',*['- '+x for x in run['events']]]
    text='\n\n'.join(md)+'\n';atomic(d/'technical.md',text)
    style='body{font:16px system-ui;max-width:1100px;margin:40px auto;background:#101927;color:#edf3fc;padding:24px}h1{color:#69e5c1}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#69e5c1}'
    head='<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>Secaudit report</title><style>'+style+'</style>'
    atomic(d/'technical.html',head+'<h1>Secaudit / Technical report</h1><pre>'+html.escape(text)+'</pre>')
    executive=f"Assessment {run['id']}\nMode: {run['mode']}\nState: {run['status']}\nCandidate findings: {len(run['findings'])}\n\n"+'\n'.join(LIMITATIONS)+'\n\nCoverage:\n'+'\n'.join(x['module']+': '+x['status'] for x in run['coverage'])+'\n\nEvents:\n'+'\n'.join(run['events'])
    atomic(d/'executive.html',head+'<h1>Secaudit / Executive report</h1><pre>'+html.escape(executive)+'</pre>')
    atomic(d/'remediation-retest.md','# Remediation and retest plan\n\n'+'\n\n'.join(f"- {f['id']} ({f['severity']}): {f['remediation']} Retest: {f['retest']}" for f in run['findings']))
    results=[]
    for f in run['findings']:
        if f['line']>0:
            from urllib.parse import quote
            results.append({'ruleId':f['rule'],'level':'warning','message':{'text':f['description']},'locations':[{'physicalLocation':{'artifactLocation':{'uri':quote(f['asset'],safe='/')},'region':{'startLine':f['line']}}}]})
    write_json(d/'findings.sarif',{'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'secaudit','version':__import__('secaudit').__version__}},'results':results}]})
    write_json(d/'sbom.cdx.json',{'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':run['components']})
    if run.get('external_sbom'): write_json(d/'external-sbom.cdx.json',run['external_sbom'])
    try:
        from .pdf_report import pdf_reports
        pdf_reports(d,run)
    except ImportError:
        atomic(d/'pdf-unavailable.txt','PDF renderer missing. Run initial setup.\n')
    if run.get('ai_suggestions'): write_json(d/'ai-suggestions.json',run['ai_suggestions'])
