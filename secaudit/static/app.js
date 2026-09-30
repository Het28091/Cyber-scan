'use strict';
// Guided controls are initialized after the existing dashboard handlers below.
const $=s=>document.querySelector(s);const $$=s=>[...document.querySelectorAll(s)];
const state={runs:[],jobs:[],details:new Map(),comparisons:new Map(),csrf:'',selected:'',view:'overview',submitted:''};
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;}
function empty(parent,title,text){parent.replaceChildren();const box=el('div','empty');box.append(el('span','empty-symbol','◎'),el('h3','',title),el('p','',text));parent.append(box);}
function notify(text,error=false){const n=$('#notice');n.hidden=false;n.className=error?'error':'';n.textContent=text;}
async function api(path,options={}){const response=await fetch(path,{...options,headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf,...options.headers}});const data=await response.json();if(!response.ok)throw Error(data.error||'Request failed');return data;}
const pretty=s=>String(s||'').replaceAll('_',' ').toLowerCase().replace(/^./,c=>c.toUpperCase());
const date=s=>s?new Date(s).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'—';
function badge(status){const cls=/FAILED|CANCELLED/.test(status)?'red':/RUNNING|QUEUED|PARTIAL|LIMITATIONS|NOT TESTED|INTERRUPTED/.test(status)?'amber':'green';return el('span','badge '+cls,pretty(status).replace('Completed with limitations','Completed · limited'));}
function navigate(view){state.view=view;$$('.view').forEach(n=>n.hidden=n.id!=='view-'+view);$$('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===view));$('#breadcrumb-view').textContent=pretty(view);const titles={overview:['Assessment overview','Understand your exposure. Keep the evidence.'],assessments:['Assessments','Manage scoped tests and review your assessment history.'],findings:['Findings explorer','Trace every candidate finding back to its evidence.'],reports:['Reports & evidence','Turn observations into clear remediation and retest plans.'],coverage:['Coverage & limitations','See exactly what was tested, and what still needs review.']};$('#page-title').textContent=titles[view][0];$('#page-subtitle').textContent=titles[view][1];if(view==='findings')renderFindings();if(view==='reports')renderReports();if(view==='coverage')renderCoverage();}
async function detail(id){if(!id)return null;if(!state.details.has(id))state.details.set(id,await api('/api/runs/'+id));return state.details.get(id);}
function choose(id,view='findings'){state.selected=id;$$('#finding-run,#report-run,#coverage-run').forEach(s=>s.value=id);navigate(view);}
function renderRuns(parent,runs){parent.replaceChildren();if(!runs.length){empty(parent,'No runs yet','Start an assessment to build your evidence history.');return;}for(const r of runs){const row=el('div','run-row');row.append(el('span','run-icon',r.mode==='offline'?'⌘':'◇'));const info=el('div','run-content');const name=el('button','run-name','Assessment '+r.id.slice(0,8));name.onclick=()=>choose(r.id);info.append(name,el('small','',date(r.started)+' · '+pretty(r.mode)));const count=el('div','run-number');count.append(el('strong','',r.findings),el('span','','findings'));row.append(info,badge(r.status),count);parent.append(row);}}
function updateSelects(){for(const select of $$('#finding-run,#report-run,#coverage-run')){select.replaceChildren();if(!state.runs.length)select.append(new Option('No assessments',''));for(const r of state.runs)select.append(new Option(r.id.slice(0,8)+' · '+date(r.started),r.id));select.value=state.selected;}}
async function refresh(){try{[state.runs,state.jobs]=await Promise.all([api('/api/runs'),api('/api/jobs')]);const submitted=state.jobs.find(j=>j.id===state.submitted);if(submitted&&!['QUEUED','RUNNING'].includes(submitted.status)){notify('Assessment '+submitted.id.slice(0,8)+' '+pretty(submitted.status).toLowerCase()+'. Review coverage and saved evidence.',submitted.status==='FAILED');state.submitted='';}state.details.clear();if(!state.selected||!state.runs.some(r=>r.id===state.selected))state.selected=state.runs[0]?.id||'';updateSelects();$('#nav-count').textContent=state.runs.length;$('#stat-runs').textContent=state.runs.length;$('#stat-findings').textContent=state.runs.reduce((n,r)=>n+r.findings,0);$('#stat-high').textContent=state.runs.reduce((n,r)=>n+r.high,0);$('#stat-active').textContent=state.jobs.filter(j=>['QUEUED','RUNNING'].includes(j.status)).length;renderRuns($('#recent-runs'),state.runs.slice(0,5));renderRuns($('#all-runs'),state.runs);renderJobs();renderGlance();if(state.view==='findings')await renderFindings();if(state.view==='reports')await renderReports();if(state.view==='coverage')await renderCoverage();}catch(e){notify(e.message,true);}}
function renderJobs(){const p=$('#jobs-list');p.replaceChildren();for(const j of state.jobs.filter(j=>['QUEUED','RUNNING','FAILED','INTERRUPTED'].includes(j.status)).slice(0,10)){const n=el('div','job');n.append(badge(j.status),el('span','',j.id.slice(0,8)+' · '+pretty(j.kind)));if(['QUEUED','RUNNING'].includes(j.status)){const b=el('button','secondary','Cancel');b.onclick=async()=>{try{await api('/api/jobs/'+j.id+'/cancel',{method:'POST',body:'{}'});await refresh();}catch(e){notify(e.message,true);}};n.append(b);}else n.append(el('span','',j.diagnostic?.message||'Review preflight output and local configuration.'));p.append(n);}}
function renderGlance(){const p=$('#coverage-glance');p.replaceChildren();const coverage=state.runs[0]?.coverage;if(!coverage){p.append(el('div','empty-small','Run an assessment to see coverage.'));return;}for(const c of coverage.slice(0,6)){const row=el('div','coverage-row');const label=el('div','coverage-label');label.append(el('span','',pretty(c.module)),el('span','',c.status));const track=el('div','track');track.append(el('span','coverage-indicator '+(c.status==='NOT TESTED'?'not-tested':''),c.status==='NOT TESTED'?'Not executed':'Limited checks executed'));row.append(label,track);p.append(row);}}
async function renderFindings(){const p=$('#findings-list');const r=await detail(state.selected);if(!r){empty(p,'No findings to show','Choose or create an assessment first.');return;}const query=$('#finding-search').value.toLowerCase(),severity=$('#finding-severity').value;const fs=r.findings.filter(f=>(!severity||f.severity===severity)&&[f.title,f.asset,f.rule].join(' ').toLowerCase().includes(query));p.replaceChildren();if(!fs.length){empty(p,'No matching findings','Review coverage before drawing conclusions about security.');return;}const table=el('table');const head=el('tr');for(const s of ['FINDING / ASSET','SEVERITY','CONFIDENCE','STATUS'])head.append(el('th','',s));const th=el('thead');th.append(head);table.append(th);const body=el('tbody');for(const f of fs){const tr=el('tr');const td=el('td');const b=el('button','finding-button',f.title);b.onclick=()=>showFinding(f,r.id);td.append(b,el('span','asset',f.asset+(f.line?':'+f.line:'')));const sev=el('td');sev.append(el('span','badge severity-'+f.severity,f.severity));tr.append(td,sev,el('td','',pretty(f.confidence)),el('td','',pretty(f.validation_status)));body.append(tr);}table.append(body);const wrap=el('div','table-wrap');wrap.append(table);p.append(wrap);}
function showFinding(f,runId=state.selected){const p=$('#finding-detail');const title=el('h2','',f.title);title.id='finding-title';p.replaceChildren(title);const meta=el('div','detail-meta');meta.append(el('span','badge severity-'+f.severity,f.severity),el('span','badge',f.confidence),el('span','badge',f.validation_status));p.append(meta);for(const [title,text] of [['Asset',f.asset+(f.line?':'+f.line:'')],['Observation',f.description],['Evidence',f.evidence.join('\n')],['Impact',f.impact],['Remediation',f.remediation],['Retest',f.retest],['Provenance',f.scanner+' '+f.scanner_version+' · '+f.rule],['Related frameworks',(f.mappings||[]).map(m=>m.framework+' '+m.version+' / '+m.control+' — '+m.status).join('\n')]]){const b=el('section','detail-block');b.append(el('h3','',title),el('p','',text||'Not mapped'));p.append(b);}renderReview(p,f,runId);$('#finding-dialog').showModal();}
async function renderReports(){const p=$('#report-list');p.replaceChildren();const r=await detail(state.selected);if(!r){empty(p,'No reports yet','Reports appear when an assessment finishes.');return;}const cards=[['JSON','AI suggestions','Untrusted assistance linked to existing finding IDs.','ai-suggestions.json'],['JSON','Assessment provenance','Modes, provider usage, events and coverage.','run.json'],['JSON','Inventory completeness','Exact pins, unresolved declarations, unsupported records and parse errors.','inventory.json'],['PDF','Executive report','Summary, boundaries, and priority remediation.','executive.pdf'],['PDF','Technical report','Findings, evidence, remediation, and retesting.','technical.pdf'],['HTML','Technical web report','A standalone report with local assets.','technical.html'],['JSON','Normalized findings','Structured evidence for downstream tools.','findings.json'],['CSV','Coverage matrix','Executed, partial, and not-tested checks.','coverage.csv'],['SARIF','Code findings','Source findings in a portable analysis format.','findings.sarif'],['CSV','Framework mappings','Reviewed related-evidence mappings.','framework-mappings.csv'],['JSON','Software inventory','CycloneDX component inventory.','sbom.cdx.json'],['JSON','Preflight report','Readiness, missing tools, and policy checks.','preflight_report.json']];for(const [format,title,desc,file] of cards){if(!(r.available_reports||[]).includes(file))continue;const card=el('article','report-card');const a=el('a','download','Download '+format+' ↓');a.href='/reports/'+r.id+'/'+file;a.download=file;card.append(el('span','format',format),el('h3','',title),el('p','',desc),a);p.append(card);}renderRetest(p,r);}
async function renderCoverage(){const p=$('#coverage-list');const r=await detail(state.selected);p.replaceChildren();if(!r){empty(p,'Coverage is not available yet','Run an assessment to establish what was actually tested.');return;}const table=el('table');const head=el('tr');['MODULE','STATUS','EVIDENCE / LIMITATION'].forEach(s=>head.append(el('th','',s)));table.append(head);for(const c of r.coverage){const row=el('tr');const status=el('td');status.append(badge(c.status));row.append(el('td','',pretty(c.module)),status,el('td','',c.reason));table.append(row);}const wrap=el('div','table-wrap');wrap.append(table);p.append(wrap);if(r.ai_usage?.enabled)p.append(el('p','muted','AI assistance (untrusted): '+JSON.stringify(r.ai_usage)));if(r.online_advisories)p.append(el('p','muted','OSV online lookups: '+r.online_advisories.completed+' completed; '+r.online_advisories.failed+' failed. Disclosed: package names, ecosystems and versions. No AI.'));for(const e of r.events||[])p.append(el('p','muted',e));}
$$('[data-view]').forEach(b=>b.onclick=()=>navigate(b.dataset.view));$('#refresh').onclick=refresh;$('#new-scan').onclick=()=>{$('#scan-error').textContent='';$('#scan-dialog').showModal();};$$('.close-dialog').forEach(b=>b.onclick=()=>$('#scan-dialog').close());$('.close-detail').onclick=()=>$('#finding-dialog').close();$('#finding-search').oninput=renderFindings;$('#finding-severity').onchange=renderFindings;for(const select of $$('#finding-run,#report-run,#coverage-run'))select.onchange=()=>{state.selected=select.value;updateSelects();navigate(state.view);};
$('#scan-target').oninput=()=>{$('#scope-label').hidden=!$('#scan-target').value;};$('#scan-scope').value=JSON.stringify({authorization:'Operator-owned synthetic demo only',origins:['http://127.0.0.1:3000/'],exclusions:['http://127.0.0.1:3000/admin'],environment:'local-lab',profiles:['passive'],max_requests:10,max_seconds:30,allowed_ips:['127.0.0.1']},null,2);
$('#scan-archive').onchange=()=>{if($('#scan-archive').files.length)$('#scan-source').value='';};$('#scan-preset').onchange=()=>{$('#ai-note').textContent=$('#scan-preset').value==='internet'?'Scoped targets and OSV package lookups. Package names and versions leave this machine; source and credentials stay local.':'No AI or online lookups. Public target IPs are blocked; local/private scoped targets only.';};
$('#scan-form').onsubmit=async event=>{event.preventDefault();const b=$('#submit-scan');b.disabled=true;$('#scan-error').textContent='';try{const data={source:$('#scan-source').value.trim(),target:$('#scan-target').value.trim(),preset:$('#scan-preset').value};data.target_workflow=JSON.parse($('#scan-workflow').value);data.scanners=JSON.parse($('#scan-scanners').value);if(data.preset.endsWith('-ai')){data.ai=JSON.parse($('#scan-ai').value);data.ai_disclosure_accepted=$('#ai-consent').checked;}if(data.target)data.scope=JSON.parse($('#scan-scope').value);const f=$('#scan-archive').files[0];if(f){if(f.size>10000000)throw Error('ZIP archive exceeds 10 MB.');data.archive_base64=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=reject;reader.readAsDataURL(f);});data.archive_name=f.name;}const job=await api('/api/jobs',{method:'POST',body:JSON.stringify(data)});state.submitted=job.id;$('#scan-dialog').close();notify('Assessment '+job.id.slice(0,8)+' queued. Preflight runs before scanning.');navigate('assessments');await refresh();}catch(e){$('#scan-error').textContent=e.message;}finally{b.disabled=false;}};
(async()=>{try{const b=await api('/api/bootstrap');state.csrf=b.csrf;for(const mode of b.presets.filter(x=>x.endsWith('-ai')))$('#scan-preset').append(new Option(mode+' · Experimental',mode));$('#version').textContent='v'+b.version;await refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);}catch(e){notify(e.message,true);}})();

$('#scan-preset').addEventListener('change',()=>{
 const mode=$('#scan-preset').value, enabled=mode.endsWith('-ai');
 $('#ai-controls').hidden=!enabled;$('#ai-consent').required=enabled;$('#ai-consent').checked=false;
 if(enabled){$('#ai-note').textContent='Experimental AI: explicit provider disclosure. Readiness and budgets are checked before assessment.';
 $('#scan-ai').value=JSON.stringify({enabled:true,provider:mode==='local-ai'?'ollama':'openai-compatible',endpoint:mode==='local-ai'?'http://127.0.0.1:11434':'https://api.example.invalid/v1',model:'operator-selected-model',api_key_env:'SECAUDIT_API_KEY',approved_ips:[mode==='local-ai'?'127.0.0.1':'192.0.2.1'],request_budget:2,token_budget:8192,timeout:15,failure_policy:'continue'},null,2);}
});
async function renderReview(parent,finding,runId){
 const section=el('section','detail-block');parent.append(section);
 section.append(el('h3','','Operator review'),el('p','muted','Decisions are recorded separately from scanner evidence. Do not enter credentials.'));
 try{
  const snapshot=await api('/api/runs/'+runId+'/reviews');const current=snapshot.decisions[finding.id]||{revision:0,status:'OPEN'};
  const form=el('form'),status=el('select'),note=el('textarea'),owner=el('input'),due=el('input'),evidence=el('textarea'),retest=el('select'),message=el('p','form-error');
  due.type='date';due.value=current.due_date||'';
  for(const value of ['OPEN','CONFIRMED','FALSE_POSITIVE','ACCEPTED_RISK','REMEDIATION_PENDING','RETEST_REQUESTED','RESOLVED'])status.append(new Option(pretty(value),value));status.value=current.status;
  note.value=current.note||'';note.required=true;note.maxLength=4000;owner.value=current.owner||'';owner.maxLength=120;evidence.value=current.evidence||'';evidence.maxLength=2000;
  retest.append(new Option('No retest linked',''));for(const run of state.runs.filter(x=>x.id!==runId))retest.append(new Option(run.id.slice(0,8)+' · '+date(run.started),run.id));retest.value=current.retest_run||'';
  for(const [title,input] of [['Review status',status],['Rationale',note],['Remediation owner',owner],['Due date (optional; overdue evaluated in UTC)',due],['Evidence or verification reference',evidence],['Retest assessment',retest]]){const label=el('label','',title);label.append(input);form.append(label);}
  const save=el('button','primary','Save review');save.type='submit';form.append(message,save);section.append(form);
  section.append(el('p','muted','Revision '+current.revision+' · Resolution requires your verification evidence and a matching completed retest with no repeated observation.'));
  for(const entry of snapshot.history.filter(x=>x.finding_id===finding.id))section.append(el('p','muted',date(entry.recorded_at)+' · '+pretty(entry.status)+' · '+entry.note));
  form.onsubmit=async event=>{event.preventDefault();save.disabled=true;message.textContent='';try{
   await api('/api/runs/'+runId+'/reviews/'+finding.id,{method:'POST',body:JSON.stringify({revision:current.revision,status:status.value,note:note.value,owner:owner.value,due_date:due.value,evidence:evidence.value,retest_run:retest.value})});
   section.remove();await renderReview(parent,finding,runId);notify('Operator review saved. Original scanner evidence is unchanged.');
  }catch(error){message.textContent=error.message;save.disabled=false;}};
 }catch(error){section.append(el('p','form-error',error.message));}
}
function renderRetest(parent,run){
 renderRemediation(parent,run);
 const box=el('article','report-card');box.append(el('h3','','Review and retest'));
 const review=el('a','download','Download current review history');review.href='/api/runs/'+run.id+'/reviews';review.download='operator-review.json';box.append(review);
 const label=el('label','','Compare with assessment'),select=el('select');select.append(new Option('Select a different assessment',''));for(const candidate of state.runs.filter(x=>x.id!==run.id))select.append(new Option(candidate.id.slice(0,8)+' · '+date(candidate.started),candidate.id));label.append(select);box.append(label);
 const button=el('button','secondary','Compare saved evidence'),result=el('pre');button.type='button';const saved=state.comparisons.get(run.id)||{};select.value=saved.retest||'';result.textContent=saved.result||'';select.onchange=()=>state.comparisons.set(run.id,{retest:select.value,result:''});box.append(button,result);parent.append(box);
 button.onclick=async()=>{button.disabled=true;try{if(!select.value)throw Error('Select a different assessment.');const data=await api('/api/compare/'+run.id+'/'+select.value);result.textContent=JSON.stringify(data,null,2);state.comparisons.set(run.id,{retest:select.value,result:result.textContent});}catch(error){result.textContent=error.message;}finally{button.disabled=false;}};
}

const remediationFilters=new Map();
async function renderRemediation(parent,run){
 const box=el('article','report-card remediation-board');parent.append(box);
 box.append(el('h3','','Remediation work list'),el('p','muted','Assign owners and due dates, review evidence, and track retests. Select a finding to update its operator review.'));
 try{
  const plan=await api('/api/runs/'+run.id+'/remediation');
  if(!box.isConnected)return;
  box.append(el('p','',plan.rows.length+' findings · '+plan.unassigned+' unassigned · '+plan.overdue+' overdue (UTC)'));
  const downloads=el('div','remediation-downloads');for(const format of ['json','csv']){const a=el('a','download','Download current plan · '+format.toUpperCase());a.href='/api/runs/'+run.id+'/remediation.'+format;a.download='remediation-plan.'+format;downloads.append(a);}box.append(downloads);
  const filters=el('div','remediation-filters'),status=el('select'),owner=el('select'),urgency=el('select');
  status.append(new Option('All review statuses',''));for(const value of Object.keys(plan.counts))status.append(new Option(pretty(value)+' ('+plan.counts[value]+')',value));
  owner.append(new Option('All owners',''),new Option('Unassigned','unassigned'));for(const value of [...new Set(plan.rows.map(r=>r.owner).filter(Boolean))].sort())owner.append(new Option(value,'owner:'+value));
  urgency.append(new Option('All due dates',''),new Option('Overdue','overdue'),new Option('No due date','none'));
  for(const [title,input] of [['Review status',status],['Owner',owner],['Due date',urgency]]){const label=el('label','',title);label.append(input);filters.append(label);}
  const saved=remediationFilters.get(run.id)||{};status.value=saved.status||'';owner.value=saved.owner||'';urgency.value=saved.urgency||'';
  const content=el('div','table-wrap');box.append(filters,content,el('p','muted',plan.limitation));
  function draw(){
   remediationFilters.set(run.id,{status:status.value,owner:owner.value,urgency:urgency.value});content.replaceChildren();
   const rows=plan.rows.filter(r=>(!status.value||r.status===status.value)&&(!owner.value||(owner.value==='unassigned'?!r.owner:'owner:'+r.owner===owner.value))&&(!urgency.value||(urgency.value==='overdue'?r.overdue:!r.due_date)));
   if(!rows.length){content.append(el('p','muted','No findings match these filters.'));return;}
   const table=el('table'),head=el('thead'),header=el('tr'),body=el('tbody');for(const title of ['Finding','Severity','Operator status','Owner','Due date'])header.append(el('th','',title));head.append(header);table.append(head,body);
   for(const row of rows){const tr=el('tr'),finding=el('td'),button=el('button','finding-button',row.title);button.onclick=()=>{const f=run.findings.find(f=>f.id===row.finding_id);if(f)showFinding(f,run.id);};finding.append(button,el('span','asset',row.asset));const severity=el('td');severity.append(el('span','badge severity-'+row.severity,row.severity));tr.append(finding,severity,el('td','',pretty(row.status)),el('td','',row.owner||'Unassigned'),el('td',row.overdue?'form-error':'',row.due_date?(row.due_date+(row.overdue?' · Overdue':'')):'Not set'));body.append(tr);}
   content.append(table);
  }
  for(const select of [status,owner,urgency])select.onchange=draw;draw();
 }catch(error){box.append(el('p','form-error','Remediation plan unavailable: '+error.message));}
}

const assessmentEditor={};
function setupGuidedAssessment(){
 const form=$('#scan-form'), target=$('#scan-target');
 const modeLabel=el('label','','Configuration editor'),mode=el('select');
 mode.append(new Option('Guided setup','guided'),new Option('Advanced JSON','json'));
 modeLabel.append(mode);target.parentElement.after(modeLabel);
 const help=el('p','muted','Only the selected editor is submitted. Guided submission replaces the JSON fields; switching editors does not import JSON into guided controls. Credentials must be environment variable names on the server.');
 modeLabel.after(help);
 const scopeBox=el('fieldset','guided-settings'),workflowBox=el('fieldset','guided-settings'),scannerBox=el('fieldset','guided-settings'),aiBox=el('div','guided-settings');
 scopeBox.append(el('legend','','Target authorization'));workflowBox.append(el('legend','','Target workflows'));scannerBox.append(el('legend','','Additional scanners'));
 help.after(scopeBox,workflowBox,scannerBox);$('#scan-ai').parentElement.before(aiBox);
 function field(parent,title,value='',kind='text'){
  const label=el('label','',title),input=el(kind==='lines'?'textarea':'input');
  if(kind==='lines')input.rows=3;else input.type=kind;
  input.value=value;label.append(input);parent.append(label);return input;
 }
 function choice(parent,title,values){const label=el('label','',title),select=el('select');for(const [value,name] of values)select.append(new Option(name,value));label.append(select);parent.append(label);return select;}
 function toggle(parent,title){const input=field(parent,title,'','checkbox');input.parentElement.className='checkline';return input;}
 const lines=input=>input.value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
 const text=input=>input.value.trim();
 function required(input,title){if(!text(input))throw Error(title+' is required.');return text(input);}
 function number(input,title,min,max){const value=Number(input.value);if(!text(input)||!Number.isInteger(value)||value<min||value>max)throw Error(title+' must be '+min+'–'+max+'.');return value;}
 const authorization=field(scopeBox,'Authorization reference'),environment=field(scopeBox,'Environment','local-lab');
 const origins=field(scopeBox,'Authorized URL prefixes — one per line','','lines'),exclusions=field(scopeBox,'Excluded URL prefixes — one per line','','lines'),pins=field(scopeBox,'Approved target IP addresses — one per line','','lines');
 const requests=field(scopeBox,'Maximum requests','10','number'),seconds=field(scopeBox,'Maximum duration (seconds)','30','number');
 workflowBox.append(el('p','muted','Choose only authorized test-account operations. Browser snapshots render fetched HTML with application scripts and network access disabled.'));
 const loginEnabled=toggle(workflowBox,'Verify login, logout and session invalidation'),loginBox=el('div');workflowBox.append(loginBox);
 const loginUrl=field(loginBox,'Login URL'),credentials=field(loginBox,'Credentials JSON environment variable','SECAUDIT_TARGET_LOGIN'),token=field(loginBox,'Response token field','token'),verifyUrl=field(loginBox,'Protected verification URL'),logoutUrl=field(loginBox,'Logout URL');
 loginBox.hidden=true;loginEnabled.onchange=()=>loginBox.hidden=!loginEnabled.checked;
 const rolesBox=el('div'),roles=[];workflowBox.append(rolesBox);
 const addRole=el('button','secondary','Add role check');addRole.type='button';workflowBox.append(addRole);
 addRole.onclick=()=>{
  if(roles.length>=10)return;
  const box=el('fieldset','guided-settings');box.append(el('legend','','Role check'));
  const role={box,name:field(box,'Role name'),url:field(box,'Protected URL'),kind:choice(box,'Authentication',[['bearer','Bearer token'],['cookie','Session cookie']]),env:field(box,'Credential environment variable','SECAUDIT_TARGET_ROLE'),status:choice(box,'Expected HTTP status',[['200','200 — allowed'],['401','401 — unauthenticated'],['403','403 — denied'],['404','404 — hidden']])};
  box.append(el('p','muted','For JSON response assertions, use advanced JSON. Credential scope is limited to this URL’s origin and path prefix.'));
  const remove=el('button','secondary','Remove role');remove.type='button';remove.onclick=()=>{roles.splice(roles.indexOf(role),1);box.remove();addRole.disabled=false;};box.append(remove);roles.push(role);rolesBox.append(box);addRole.disabled=roles.length>=10;
 };
 const cors=field(workflowBox,'CORS probe URLs — one per line (up to 10)','','lines'),browser=field(workflowBox,'Browser snapshot URLs — one per line (up to 5)','','lines'),browserExecutable=field(workflowBox,'Browser executable path (optional)');
 const scanners={};for(const name of ['gitleaks','semgrep','trivy','syft']){
  const enabled=toggle(scannerBox,'Enable '+name),box=el('div');box.hidden=true;scannerBox.append(box);enabled.onchange=()=>box.hidden=!enabled.checked;
  scanners[name]={enabled,executable:field(box,name+' executable path (optional)')};
  if(name==='semgrep')scanners[name].rules=field(box,'Reviewed local rules path');
  if(name==='trivy')scanners[name].cache=field(box,'Prepared vulnerability database cache path');
 }
 const endpoint=field(aiBox,'Provider endpoint'),model=field(aiBox,'Model name'),aiPins=field(aiBox,'Approved provider IP addresses — one per line','','lines'),key=field(aiBox,'API key environment variable','SECAUDIT_API_KEY');
 const aiRequests=field(aiBox,'Request budget','2','number'),aiTokens=field(aiBox,'Token budget','8192','number'),aiTimeout=field(aiBox,'Request timeout (seconds)','15','number'),failure=choice(aiBox,'If AI is unavailable',[['continue','Continue without AI'],['required','Require AI readiness']]);
 const advanced=[$('#scope-label'),$('#scan-workflow').parentElement,$('#scan-scanners').parentElement,$('#scan-ai').parentElement];
 function visibility(){const guided=mode.value==='guided',hasTarget=!!text(target);scopeBox.hidden=!guided||!hasTarget;workflowBox.hidden=!guided||!hasTarget;scannerBox.hidden=!guided;aiBox.hidden=!guided;advanced.forEach(n=>n.hidden=guided);$('#scope-label').hidden=guided||!hasTarget;}
 mode.onchange=visibility;target.addEventListener('input',visibility);
 $('#scan-preset').addEventListener('change',()=>{const local=$('#scan-preset').value==='local-ai';endpoint.value=local?'http://127.0.0.1:11434':'';aiPins.value=local?'127.0.0.1':'';key.parentElement.hidden=local;});
 function sync(){
  if(mode.value!=='guided')return;
   const workflow={},scannerConfig={};
   if(text(target)){
    if(loginEnabled.checked)workflow.login={url:required(loginUrl,'Login URL'),credentials_env:required(credentials,'Credentials environment variable'),token_field:required(token,'Token field'),verify_url:required(verifyUrl,'Verification URL'),logout_url:required(logoutUrl,'Logout URL')};
    if(roles.length)workflow.roles=roles.map(role=>{const url=new URL(required(role.url,'Role URL'));return {name:required(role.name,'Role name'),url:role.url.value.trim(),authentication:{type:role.kind.value,env:required(role.env,'Role credential variable'),origin:url.origin,paths:[url.pathname]},expected_status:Number(role.status.value)};});
    if(lines(cors).length)workflow.cors=lines(cors);
    if(lines(browser).length){workflow.browser={urls:lines(browser)};if(text(browserExecutable))workflow.browser.executable=text(browserExecutable);}
    if(!lines(origins).length||!lines(pins).length)throw Error('Explicit authorized URL prefixes and target IP addresses are required.');
    $('#scan-scope').value=JSON.stringify({authorization:required(authorization,'Authorization reference'),environment:required(environment,'Environment'),origins:lines(origins),exclusions:lines(exclusions),allowed_ips:lines(pins),profiles:Object.keys(workflow).length?['passive','bounded']:['passive'],max_requests:number(requests,'Request budget',1,100),max_seconds:number(seconds,'Duration',1,300)},null,2);
   }
   for(const [name,options] of Object.entries(scanners))if(options.enabled.checked){scannerConfig[name]={};for(const option of ['executable','rules','cache'])if(options[option]&&text(options[option]))scannerConfig[name][option]=text(options[option]);}
   $('#scan-workflow').value=JSON.stringify(workflow,null,2);$('#scan-scanners').value=JSON.stringify(scannerConfig,null,2);
   if($('#scan-preset').value.endsWith('-ai')){
    if(!lines(aiPins).length)throw Error('Approved provider IP addresses are required.');
    $('#scan-ai').value=JSON.stringify({enabled:true,provider:$('#scan-preset').value==='local-ai'?'ollama':'openai-compatible',endpoint:required(endpoint,'Provider endpoint'),model:required(model,'Model name'),api_key_env:required(key,'API key variable'),approved_ips:lines(aiPins),request_budget:number(aiRequests,'AI request budget',1,1000000),token_budget:number(aiTokens,'AI token budget',1,1000000),timeout:number(aiTimeout,'AI timeout',1,120),failure_policy:failure.value},null,2);
   }
 }
 assessmentEditor.sync=sync;
 assessmentEditor.load=data=>{
  mode.value='json';$('#scan-source').value=data.source||'';target.value=data.target||'';
  $('#scan-preset').value=data.preset||'internet';$('#scan-preset').dispatchEvent(new Event('change'));
  $('#scan-scope').value=JSON.stringify(data.scope||{},null,2);$('#scan-workflow').value=JSON.stringify(data.target_workflow||{},null,2);
  $('#scan-scanners').value=JSON.stringify(data.scanners||{},null,2);$('#scan-ai').value=JSON.stringify(data.ai||{},null,2);
  $('#scan-archive').value='';$('#scan-authorized').checked=false;$('#ai-consent').checked=false;visibility();
 };
 // Capture runs before the existing submit handler constructs its request.
 form.addEventListener('submit',event=>{
  try{sync();}catch(error){event.preventDefault();event.stopImmediatePropagation();$('#scan-error').textContent=error.message;}
 },true);
 visibility();
}
setupGuidedAssessment();

function setupAssessmentProfiles(){
 const box=el('fieldset','guided-settings');box.append(el('legend','','Reusable assessment setup'));
 const select=el('select'),name=el('input');name.maxLength=100;name.placeholder='Example: owned staging API';
 for(const [title,input] of [['Saved profile',select],['Profile name',name]]){const label=el('label','',title);label.append(input);box.append(label);}
 box.append(el('p','muted','Profiles save configuration on this server, including local paths and scope. Use environment variable names only; never enter secrets. ZIP contents and authorization consent are not saved. Loading uses the advanced editor.'));
 const actions=el('div','profile-actions'),message=el('p','muted'),summary=el('pre','configuration-summary');summary.hidden=true;message.setAttribute('role','status');box.append(actions,message,summary);
 $('#scan-source').parentElement.before(box);
 let profiles=[],busy=false;
 function button(title,action){const b=el('button','secondary',title);b.type='button';b.onclick=async()=>{if(busy)return;busy=true;for(const child of actions.children)child.disabled=true;message.textContent='';try{await action();}catch(error){message.textContent=error.message;}finally{busy=false;for(const child of actions.children)child.disabled=false;}};actions.append(b);return b;}
 function selected(){const profile=profiles.find(p=>p.id===select.value);if(!profile)throw Error('Choose a saved profile first.');return profile;}
 function configuration(){
  assessmentEditor.sync();
  if($('#scan-archive').files.length)throw Error('Reusable configuration requires a source directory or target. Remove the selected ZIP; archives are not saved.');
  const data={source:$('#scan-source').value.trim(),target:$('#scan-target').value.trim(),preset:$('#scan-preset').value,scanners:JSON.parse($('#scan-scanners').value),target_workflow:JSON.parse($('#scan-workflow').value)};
  if(data.target)data.scope=JSON.parse($('#scan-scope').value);
  if(data.preset.endsWith('-ai'))data.ai=JSON.parse($('#scan-ai').value);
  return data;
 }
 async function reload(id=select.value){profiles=await api('/api/profiles');select.replaceChildren(new Option('Choose a saved profile',''));for(const profile of profiles)select.append(new Option(profile.name+' · revision '+profile.revision,profile.id));select.value=id;}
 select.onchange=()=>{const profile=profiles.find(p=>p.id===select.value);name.value=profile?.name||'';summary.hidden=true;message.textContent='Selection does not change your form. Use Load selected to replace its values.';};
 button('Reload list',()=>reload());
 button('Load selected',()=>{
  const profile=selected(),data=profile.configuration;
  if(![...$('#scan-preset').options].some(o=>o.value===(data.preset||'internet')))throw Error('This profile uses a disabled mode. Enable the experimental mode on the server before loading it.');
  assessmentEditor.load(data);name.value=profile.name;summary.hidden=true;
  message.textContent='Profile loaded into advanced JSON. Review current authorization, IP pins and provider disclosure before starting.';
 });
 async function save(copy){const profile=copy?null:selected();const saved=await api('/api/profiles',{method:'POST',body:JSON.stringify({name:name.value,configuration:configuration(),...(profile?{id:profile.id,revision:profile.revision}:{})})});await reload(saved.id);message.textContent='Saved revision '+saved.revision+'. No scan was started.';}
 button('Save as new',()=>save(true));button('Update selected',()=>save(false));
 button('Delete selected',async()=>{const profile=selected();await api('/api/profiles/'+profile.id+'/delete',{method:'POST',body:JSON.stringify({revision:profile.revision})});await reload('');name.value='';message.textContent='Profile deleted. Assessment evidence is unchanged.';});
 button('Review configuration',async()=>{
  const result=await api('/api/configuration/preview',{method:'POST',body:JSON.stringify(configuration())});
  const s=result.summary;summary.textContent=[['Mode',s.mode],['Source directory',s.source||'None'],['Target',s.target||'None'],['Authorized URL prefixes',s.authorized_prefixes.join('\n')||'None'],['Excluded URL prefixes',s.excluded_prefixes.join('\n')||'None'],['Target IP pins',s.target_ip_pins.join(', ')||'None'],['Target limits',s.request_limit==null?'No target':s.request_limit+' requests / '+s.time_limit_seconds+' seconds'],['Declared workflow requests',s.workflow_requests],['Workflow operations',s.workflow_operations.join(', ')||'Passive scan'],['Additional scanners',s.scanners.join(', ')||'None'],['AI provider',s.provider],['Model',s.model||'None'],['Provider endpoint',s.provider_endpoint||'None'],['Provider IP pins',s.provider_ip_pins.join(', ')||'None'],['AI budgets',s.ai_request_budget+' requests / '+s.ai_token_budget+' tokens'],['Data disclosure',s.network_disclosure],['Review limits',s.limitation]].map(([label,value])=>label+': '+value).join('\n\n');summary.hidden=false;message.textContent='Configuration summary only. Preflight still runs when you start an assessment.';
 });
 $('#scan-form').addEventListener('input',event=>{if(!box.contains(event.target))summary.hidden=true;});
 $('#scan-form').addEventListener('change',event=>{if(!box.contains(event.target))summary.hidden=true;});
 $('#new-scan').addEventListener('click',()=>reload().catch(error=>message.textContent=error.message));
 select.append(new Option('Open or reload to list profiles',''));
}
setupAssessmentProfiles();
