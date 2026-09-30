"""Current operator action plans derived from immutable assessment evidence."""
import csv
import io
from datetime import datetime,timezone
from .models import now
from .review import Reviews,load_run,STATES
from .security import redact


def action_plan(root,ident):
    run=load_run(root,ident)
    store=Reviews(root)
    try:snapshot=store.snapshot(ident)
    finally:store.close()
    today=datetime.now(timezone.utc).date().isoformat()
    closed={'RESOLVED','FALSE_POSITIVE','ACCEPTED_RISK'}
    rows=[]
    for finding in run['findings']:
        decision=snapshot['decisions'].get(finding['id'],{})
        status=decision.get('status','OPEN');due=decision.get('due_date','')
        rows.append({
            'finding_id':finding['id'],'title':finding.get('title',''),
            'rule':finding.get('rule',''),'asset':finding.get('asset',''),
            'severity':finding.get('severity','INFO'),'status':status,
            'owner':decision.get('owner',''),'due_date':due,
            'overdue':bool(due and due<today and status not in closed),
            'revision':decision.get('revision',0),'note':decision.get('note',''),
            'evidence_reference':decision.get('evidence',''),
            'retest_run':decision.get('retest_run',''),
            'remediation':finding.get('remediation',''),'retest':finding.get('retest',''),
            'scanner_validation':finding.get('validation_status',''),
        })
    priority={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    rows.sort(key=lambda r:(r['status'] in closed,not r['overdue'],priority.get(r['severity'],5),r['due_date'] or '9999-12-31',r['finding_id']))
    return redact({'run_id':ident,'generated_at':now(),'date_basis':'UTC',
        'assessment_status':run['status'],
        'counts':{state:sum(r['status']==state for r in rows) for state in STATES},
        'overdue':sum(r['overdue'] for r in rows),
        'unassigned':sum(not r['owner'] and r['status'] not in closed for r in rows),
        'rows':rows,'limitation':'Operator decisions are separate from scanner evidence. Risk acceptance is not remediation. Missing observations do not prove resolution.'})


def action_csv(plan):
    stream=io.StringIO(newline='')
    fields=['finding_id','title','rule','asset','severity','status','owner','due_date','overdue','revision','note','evidence_reference','retest_run','remediation','retest','scanner_validation']
    writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
    for row in plan['rows']:
        # Quoting CSV alone does not stop spreadsheet formula interpretation.
        safe={key:("'"+str(value) if str(value).lstrip().startswith(('=','+','-','@')) or str(value).startswith(('\t','\r','\n')) else value) for key,value in row.items()}
        writer.writerow(safe)
    return stream.getvalue().encode('utf-8-sig')
