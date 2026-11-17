const $=id=>document.getElementById(id);
const sample={Version:'2012-10-17',Statement:[{Sid:'SyntheticBroadAgent',Effect:'Allow',Action:['iam:PassRole','lambda:InvokeFunction','secretsmanager:GetSecretValue'],Resource:'*'}]};
let report,previous,revision=0;
function node(tag,text,cls){const item=document.createElement(tag);item.textContent=text;if(cls)item.className=cls;return item;}
function select(location){$('location').textContent=`${location.snapshot||'Current'}: ${location.source}:${location.startLine}–${location.endLine} ${location.json_pointer||'/ (policy-level finding)'}`;$('evidence').textContent=location.snippet;$('evidence-box').focus();}
function emptyResults(){report=undefined;$('findings').replaceChildren();$('delta-findings').replaceChildren();$('graph').textContent='No current successful analysis.';$('headline').textContent='No analysis established';$('delta').textContent='';$('provenance').textContent='';$('location').textContent='No current statement selected.';$('evidence').textContent='No current statement evidence.';for(const id of ['sarif','human','json'])$(id).disabled=true;}
function invalidate(){revision+=1;emptyResults();}
function show(data){
  report=data;$('headline').textContent=`${data.findings.length} static pattern finding(s) · effective permissions UNKNOWN`;
  const delta=data.delta;$('delta').textContent=delta.comparison_performed?`Pattern delta: ${delta.added.length} added, ${delta.removed.length} removed · ${delta.before_count} before / ${delta.after_count} after. This is not measured AWS risk reduction.`:'First review captured. Edit and rerun to compare.';
  $('delta-findings').replaceChildren();for(const kind of ['added','removed'])for(const finding of delta[kind]){const button=node('button',`${kind==='removed'?'Before · removed':'After · added'} ${finding.rule_id} — ${finding.location.source}:${finding.location.startLine}`);button.type='button';button.addEventListener('click',()=>select({...finding.location,snapshot:kind==='removed'?'Before':'After'}));$('delta-findings').append(button);}
  $('provenance').textContent=`Run ${data.run_id} · engine ${data.app_version} · source ${data.source_commit} (${data.source_status}) · ${data.static_rule_count} static rules`;
  $('findings').replaceChildren();
  if(!data.findings.length)$('findings').append(node('p','No configured static pattern matched. This does not prove least privilege or safety.','empty'));
  for(const finding of data.findings){const card=node('article','','finding');card.append(node('p',`${finding.severity.toUpperCase()} · ${finding.rule_id}`,'severity'));const button=node('button',`${finding.location.source}:${finding.location.startLine} ${finding.location.json_pointer||'/'} — inspect evidence`);button.type='button';button.addEventListener('click',()=>select(finding.location));card.append(button,node('p',finding.message),node('p',`Remediation: ${finding.remediation}`),node('p',`Counter-evidence: Deny statements ${finding.counter_evidence.deny_statement_indices.join(', ')||'none supplied'}; condition present: ${finding.counter_evidence.conditions_present}. Intersections are not evaluated.`));$('findings').append(card);}
  $('graph').replaceChildren();const nodes=new Map(data.graph.nodes.map(item=>[item.id,item]));
  for(const statement of data.statements){const row=node('div','','graph-row');const source=node('div',statement.location.source,'node');const block=node('div','','node');const button=node('button',`Statement ${statement.index}: ${statement.effect}${Object.keys(statement.condition).length?' · conditional':''}`);button.type='button';button.addEventListener('click',()=>select(statement.location));block.append(button);const targets=node('div','','targets');for(const edge of data.graph.edges.filter(edge=>edge.from===statement.id)){targets.append(node('div',`${edge.label}: ${nodes.get(edge.to).label}`,'node'));}row.append(source,node('span','→','arrow'),block,node('span','→','arrow'),targets);$('graph').append(row);}
  $('limitations').replaceChildren(...data.limitations.map(text=>node('li',text)));for(const id of ['sarif','human','json'])$(id).disabled=false;
}
$('sample').addEventListener('click',()=>{invalidate();$('policy').value=JSON.stringify(sample,null,2);$('trust').value='';$('status').textContent='Synthetic example loaded. Run the engine to analyze it.';});
$('clear').addEventListener('click',()=>{invalidate();previous=undefined;$('status').textContent='Previous review cleared. No inputs are stored on the backend.';});
for(const id of ['policy','trust'])$(id).addEventListener('input',()=>{invalidate();$('status').textContent='Input changed. Run a new review; previous successful input is available for comparison.';});
for(const [input,target] of [['policy-file','policy'],['trust-file','trust']])$(input).addEventListener('change',async()=>{
  const file=$(input).files[0];if(!file)return;
  invalidate();const fileRevision=revision;
  if(file.size>32768){$('status').textContent='File exceeds the 32768-byte limit.';return;}
  try{
    const text=await file.text();
    // A newer file choice or edit takes precedence over this asynchronous read.
    if(revision!==fileRevision)return;
    // A real review may have completed while the file was loading. Its results
    // cannot describe the new editor contents, even if no input event fired.
    invalidate();$(target).value=text;
    $('status').textContent='Local file loaded into the editor. It has not been analyzed.';
  }catch(error){if(revision===fileRevision){invalidate();$('status').textContent='The local file could not be read. Select it again.';}}
});
$('compare').addEventListener('change',()=>{invalidate();$('status').textContent='Comparison option changed. Run a new review.';});
$('review').addEventListener('click',async()=>{
  $('review').disabled=true;emptyResults();$('status').textContent='Running the actual local static scanners…';
  const startedRevision=revision;const payload={policy:$('policy').value,trust:$('trust').value};if(previous&&$('compare').checked){payload.before_policy=previous.policy;payload.before_trust=previous.trust;}
  try{const response=await fetch('/api/review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await response.json();if(!response.ok)throw new Error(data.error||'Analysis failed');if(revision!==startedRevision||$('policy').value!==payload.policy||$('trust').value!==payload.trust)throw new Error('Input changed during review. Run the engine again for current text.');show(data);previous={policy:payload.policy,trust:payload.trust};$('status').textContent='Static review complete. Inspect evidence and limitations.';}catch(error){emptyResults();$('status').textContent=error.message;}finally{$('review').disabled=false;}
});
function download(value,type,name){const url=URL.createObjectURL(new Blob([value],{type}));const link=node('a','');link.href=url;link.download=name;link.click();URL.revokeObjectURL(url);}
$('sarif').addEventListener('click',()=>download(JSON.stringify(report.sarif,null,2),'application/sarif+json',`iam-${report.run_id}.sarif`));
$('human').addEventListener('click',()=>download(report.human_report,'text/plain',`iam-${report.run_id}.txt`));
$('json').addEventListener('click',()=>download(JSON.stringify(report,null,2),'application/json',`iam-${report.run_id}.json`));
