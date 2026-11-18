from pathlib import Path
import json,re,subprocess,threading,urllib.request,datetime,os,hashlib
from aws_agent_identity_guard.studio.__main__ import create_server
r=Path('/workspace/work/candidates/aws-agent-identity-guard');out=Path('/workspace/work/doc-reconciliation/aws-agent-identity-guard');checks=[]
for n in subprocess.check_output(['git','ls-files'],cwd=r,text=True).splitlines():
 p=r/n
 if p.suffix!='.md':continue
 for lang,body in re.findall(r'^```([^\n]*)\n(.*?)^```',p.read_text(),re.M|re.S):
  if lang.strip() in ['sh','bash']:
   q=subprocess.run(['bash','-n'],input=body,text=True,capture_output=True);checks.append({'document':n,'check':'shell syntax only, not execution','exit_code':q.returncode,'stderr':q.stderr});assert q.returncode==0,(n,q.stderr)
  if lang.strip()=='json':json.loads(body);checks.append({'document':n,'check':'JSON example syntax','exit_code':0})
body=re.search(r'^```json\n(.*?)^```',(r/'docs/STUDIO.md').read_text(),re.M|re.S).group(1);payload=json.loads(body);server=create_server(0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
 req=urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/api/review',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=10) as resp:report=json.load(resp)
 assert report['effective_permissions']=='UNKNOWN' and len(report['findings'])>0 and report['sarif']['version']=='2.1.0';(out/'actual-api-example.json').write_text(json.dumps(report,indent=2)+'\n');checks.append({'document':'docs/STUDIO.md','check':'actual documented API envelope through own fresh loopback server and canonical static scanners','observed_source':report['source_commit'],'observed_source_status':report['source_status'],'finding_count':len(report['findings']),'effective_permissions':report['effective_permissions'],'exit_code':0})
finally:server.shutdown();server.server_close();thread.join(2)
py='/workspace/work/envs/iam/bin/python';env={**os.environ,'PYTHONPATH':str(r/'src'),'PYTHONDONTWRITEBYTECODE':'1','AWS_EC2_METADATA_DISABLED':'true'}
for name,tail,expected in [('version',['--version'],0),('json',['examples/agent_policy_wildcard.json','--format','json'],1),('sarif',['examples/agent_policy_wildcard.json','--format','sarif','--output',str(out/'actual-cli-example.sarif')],1),('remediation',['examples/agent_policy_wildcard.json','--remediate'],1)]:
 cmd=[py,'-m','aws_agent_identity_guard.cli',*tail];p=subprocess.run(cmd,cwd=r,env=env,text=True,capture_output=True,timeout=20);(out/('cli-'+name+'.log')).write_text(p.stdout+p.stderr);assert p.returncode==expected,(name,p.returncode,p.stderr)
 if name=='json':assert json.loads(p.stdout)['findings']
 if name=='sarif':assert json.loads((out/'actual-cli-example.sarif').read_text())['version']=='2.1.0'
 if name=='remediation':assert 'GENERATED REMEDIATIONS (deterministic IaC templates)' in p.stdout and 'Terraform HCL:' in p.stdout
 checks.append({'document':'RUNBOOK.md','check':'actual CLI '+name+' example, local synthetic fixture; finding exit1 is expected','command':cmd,'exit_code':p.returncode,'expected_exit_code':expected})
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Document syntax plus named actual offline examples only; shell syntax is not all commands executed and source status is explicitly observed','checks':checks};(out/'example-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('Documentation checks passed:',len(checks))
