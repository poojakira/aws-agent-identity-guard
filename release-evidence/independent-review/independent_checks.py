"""Independent offline IAM studio checks against real engines and browser."""
import datetime
import hashlib
import http.client
import json
import pathlib
import subprocess
import threading
import time

from jsonschema import Draft4Validator, FormatChecker
from playwright.sync_api import expect, sync_playwright

from aws_agent_identity_guard.scanner import scan_policy_document
from aws_agent_identity_guard.studio.__main__ import create_server
from aws_agent_identity_guard.studio.analysis import Document, InputError, review_change

ROOT = pathlib.Path('/workspace/work/candidates/aws-agent-identity-guard')
OUT = pathlib.Path('/workspace/work/reviews/aws-agent-identity-guard/remediation-970d1e1')
EVIDENCE = pathlib.Path('/workspace/work/evidence/aws-agent-identity-guard/final')
SCHEMA = pathlib.Path('/workspace/work/references/sarif-schema-2.1.0.json')
sha = subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
result = {'source_commit':sha,'utc_start':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':[]}

def record(name, passed, **details):
    result['checks'].append({'name':name,'passed':bool(passed),**details})

def policy(action='s3:ListBucket', resource='*'):
    return {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':action,'Resource':resource}]}

manifest=json.loads((EVIDENCE/'manifest.json').read_text())
mismatches=[p for p,h in manifest['artifacts'].items() if hashlib.sha256((EVIDENCE/p).read_bytes()).hexdigest()!=h]
record('final manifest artifact checksums',not mismatches,artifacts=len(manifest['artifacts']),mismatches=mismatches)
record('manifest source and clean checkout',manifest['source_commit']==sha and not subprocess.check_output(['git','-C',str(ROOT),'status','--porcelain'],text=True).strip())

raw='''{
 "Id":"Statement in an escaped string: \\"not syntax\\"",
 "St\\u0061tement":[
  {"Sid":"first","Effect":"Deny","Action":"s3:GetObject","Resource":"*"},
  {"Sid":"second","Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}
 ]
}'''
doc=Document(raw,'identity')
review=review_change({'policy':raw})
location=doc.location(1)
expected_line=raw[:raw.index('{"Sid":"second"')].count('\n')+1
record('escaped structural key and exact statement span',location['startLine']==expected_line and location['endLine']==expected_line and json.loads(location['snippet'])==json.loads(raw)['Statement'][1],location=location)
for finding in review['findings']:
    if finding['statement_index'] is not None:
        record('finding location matches its actual statement '+finding['rule_id'],json.loads(finding['location']['snippet'])==doc.statements[finding['statement_index']])
record('Deny and conditions are explicit context',all(f['counter_evidence']['deny_statement_indices']==[0] for f in review['findings']) and review['effective_permissions']=='UNKNOWN')
record('canonical scanner produces displayed identity findings',[f['rule_id'] for f in review['findings']]==[f.rule_id for f in scan_policy_document(doc.value)])

list_review=review_change({'policy':json.dumps(policy(),indent=2)})
list_findings=[f for f in list_review['findings'] if f['rule_id'] in ('AIG003','AIG007')]
record('list-only findings do not assert arbitrary data reads',all('read all accessible secrets/data' not in f['message'] and 'access to all resources in the account' not in f['message'] for f in list_findings),findings=[{'rule_id':f['rule_id'],'message':f['message']} for f in list_findings])
(OUT/'list-only-review.json').write_text(json.dumps(list_review,indent=2)+'\n')

for name,bad in [
    ('escaped duplicate key','{"Statement":{"Effect":"Allow","Action":"*","\\u0041ction":"s3:GetObject","Resource":"*"}}'),
    ('trailing JSON',json.dumps(policy())+'{}'),
    ('non-finite condition','{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"x":1e999}}}}'),
    ('too-deep JSON','['*18+'0'+']'*18),
    ('oversized policy',' '*32769),
    ('non-object statement','{"Statement":[3]}'),
    ('non-string action',json.dumps(policy(17))),
    ('oversized object key',json.dumps({'Statement':{'Effect':'Allow','Action':'*','Resource':'*','Condition':{'StringEquals':{'k'*4097:'v'}}}})),
]:
    try:
        review_change({'policy':bad})
        accepted=True
    except InputError:
        accepted=False
    record(name+' rejected',not accepted)

trust={'Statement':{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'AWS':'arn:aws:iam::123456789012:role/<img src=x onerror="window.iamXss=1">'}}}
combined=review_change({'policy':json.dumps(policy('s3:GetObject','arn:aws:s3:::synthetic/*'),indent=2),'trust':json.dumps(trust,indent=2)})
schema_bytes=SCHEMA.read_bytes()
record('official schema bytes match pinned checksum',hashlib.sha256(schema_bytes).hexdigest()=='c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e')
validator=Draft4Validator(json.loads(schema_bytes),format_checker=FormatChecker())
validator.validate(combined['sarif'])
record('actual identity and trust SARIF validate',len(combined['sarif']['runs'])==2)
locations_agree=True
for run in combined['sarif']['runs']:
    for item in run['results']:
        physical=item['locations'][0]['physicalLocation'];source=physical['artifactLocation']['uri'];matching=[f for f in combined['findings'] if f['rule_id']==item['ruleId'] and f['location']['source']==source]
        if not any(f['location']['startLine']==physical['region']['startLine'] and f['location']['endLine']==physical['region']['endLine'] for f in matching):locations_agree=False
record('SARIF source regions match actual evidence',locations_agree)
(OUT/'independent.sarif').write_text(json.dumps(combined['sarif'],indent=2)+'\n')
record('graph nodes only reference supplied document statements',all(n['id'].startswith(('identity-policy.json','trust-policy.json')) for n in combined['graph']['nodes']) and combined['effective_permissions']=='UNKNOWN')
again=review_change({'policy':json.dumps(policy())})
record('same input and configuration hash reproducibly',again['input_sha256']==review_change({'policy':json.dumps(policy())})['input_sha256'] and again['configuration_sha256']==list_review['configuration_sha256'])

server=create_server(0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();base=f'http://127.0.0.1:{server.server_port}'
def post(body,headers=None):
    c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10);c.request('POST','/api/review',body=body,headers={'Content-Type':'application/json',**(headers or {})});r=c.getresponse();status=r.status;data=json.loads(r.read());c.close();return status,data

try:
    for name,body,headers,expected in [
        ('host',json.dumps({'policy':json.dumps(policy())}),{'Host':'attacker.example'},403),
        ('origin',json.dumps({'policy':json.dumps(policy())}),{'Origin':'https://attacker.example'},403),
        ('outer duplicates','{"policy":"{}","policy":"{}"}',{},400),
        ('outer extra target',json.dumps({'policy':json.dumps(policy()),'target':'http://169.254.169.254'}),{},400),
        ('request body bound','x'*196609,{},413),
        ('outer deep body','['*1500+'0'+']'*1500,{},400),
    ]:
        status,data=post(body,headers);record('HTTP '+name,status==expected,actual=status,expected=expected)
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True)
        page=browser.new_page(viewport={'width':1280,'height':900},accept_downloads=True)
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(base);page.locator('#policy').fill(raw);page.locator('details summary').click();page.locator('#trust').fill(json.dumps(trust));page.get_by_role('button',name='Review IAM change',exact=True).click();expect(page.locator('#review')).to_be_enabled(timeout=15000);expect(page.locator('#json')).to_be_enabled()
        record('browser displays actual supplied findings and safely renders HTML',page.locator('#findings article').count()>0 and page.locator('#graph img').count()==0 and page.evaluate('window.iamXss === undefined'))
        with page.expect_download() as download:page.get_by_role('button',name='Export evidence JSON',exact=True).click()
        download.value.save_as(OUT/'browser-evidence.json');browser_report=json.loads((OUT/'browser-evidence.json').read_text());record('browser export source and input agree',browser_report['source_commit']==sha and browser_report['sources'][0]['sha256']==hashlib.sha256(raw.encode()).hexdigest())
        page.set_viewport_size({'width':390,'height':844});record('mobile essential layout bounds',page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'));page.set_viewport_size({'width':1280,'height':900})

        # Delay only file reading, while every scan still reaches the real backend.
        page.evaluate("""() => { const original=File.prototype.text; File.prototype.text=async function(){const text=await original.call(this);if(this.name==='delayed-policy.json')await new Promise(resolve=>setTimeout(resolve,1200));return text;};} """)
        new_raw=json.dumps(policy('s3:GetObject','arn:aws:s3:::independent-new-input/*'),indent=2)
        page.locator('#policy-file').set_input_files({'name':'delayed-policy.json','mimeType':'application/json','buffer':new_raw.encode()})
        page.get_by_role('button',name='Review IAM change',exact=True).click();expect(page.locator('#review')).to_be_enabled(timeout=15000);expect(page.locator('#policy')).to_have_value(new_raw)
        stale_enabled=page.locator('#json').is_enabled()
        record('file-read completion invalidates intervening real review',not stale_enabled,export_still_enabled=stale_enabled,status=page.locator('#status').inner_text(),headline=page.locator('#headline').inner_text())
        if stale_enabled:
            with page.expect_download() as download:page.get_by_role('button',name='Export evidence JSON',exact=True).click()
            download.value.save_as(OUT/'stale-file-race-export.json')
            stale=json.loads((OUT/'stale-file-race-export.json').read_text());(OUT/'stale-file-race.json').write_text(json.dumps({'source_commit':sha,'displayed_policy_sha256':hashlib.sha256(new_raw.encode()).hexdigest(),'exported_policy_sha256':stale['sources'][0]['sha256'],'export_still_enabled':stale_enabled,'different_inputs':stale['sources'][0]['sha256']!=hashlib.sha256(new_raw.encode()).hexdigest()},indent=2)+'\n')
        # Exercise trust uploads and newer edits independently of the product's test.
        page.evaluate("""() => { const prior=File.prototype.text; File.prototype.text=async function(){ const text=await prior.call(this); if(this.name.startsWith('independent-slow-')){document.body.dataset.independentFilePending=this.name; await new Promise(resolve=>setTimeout(resolve,900)); delete document.body.dataset.independentFilePending;} return text; }; }""")
        new_trust=json.dumps({'Statement':{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'AWS':'arn:aws:iam::111122223333:role/IndependentTrust'}}},indent=2)
        page.get_by_role('button',name='Review IAM change',exact=True).click();expect(page.locator('#review')).to_be_enabled(timeout=15000);expect(page.locator('#json')).to_be_enabled()
        page.locator('#trust-file').set_input_files({'name':'independent-slow-trust.json','mimeType':'application/json','buffer':new_trust.encode()})
        expect(page.locator('body')).to_have_attribute('data-independent-file-pending','independent-slow-trust.json')
        page.get_by_role('button',name='Review IAM change',exact=True).click();expect(page.locator('#review')).to_be_enabled(timeout=15000)
        expect(page.locator('#trust')).to_have_value(new_trust)
        record('trust file completion invalidates intervening real review',page.locator('#json').is_disabled(),status=page.locator('#status').inner_text())
        for field,input_id,manual,filetext in [
            ('policy','policy-file',json.dumps(policy('s3:ListBucket','arn:aws:s3:::manual-review-bucket'),indent=2),new_raw),
            ('trust','trust-file',json.dumps({'Statement':{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'lambda.amazonaws.com'}}},indent=2),new_trust),
        ]:
            name='independent-slow-'+field+'-manual.json'
            page.locator('#'+input_id).set_input_files({'name':name,'mimeType':'application/json','buffer':filetext.encode()})
            expect(page.locator('body')).to_have_attribute('data-independent-file-pending',name)
            page.locator('#'+field).fill(manual)
            page.get_by_role('button',name='Review IAM change',exact=True).click();expect(page.locator('#review')).to_be_enabled(timeout=15000);expect(page.locator('#json')).to_be_enabled()
            expect(page.locator('body')).not_to_have_attribute('data-independent-file-pending',name)
            expect(page.locator('#'+field)).to_have_value(manual)
            record('obsolete '+field+' upload does not replace newer manual review',page.locator('#json').is_enabled() and page.locator('#'+field).input_value()==manual)
            with page.expect_download() as download:page.get_by_role('button',name='Export evidence JSON',exact=True).click()
            download.value.save_as(OUT/('manual-'+field+'-review.json'));manual_report=json.loads((OUT/('manual-'+field+'-review.json')).read_text());source=next(s for s in manual_report['sources'] if s['name']==('identity-policy.json' if field=='policy' else 'trust-policy.json'))
            record('retained '+field+' evidence matches newer manual input',source['sha256']==hashlib.sha256(manual.encode()).hexdigest())
        page.screenshot(path=str(OUT/'browser-race.png'),full_page=True)
        record('no uncaught browser errors',not errors,errors=errors)
        browser.close()
finally:
    server.shutdown();server.server_close();thread.join()

lint=subprocess.run(['/workspace/work/tooling/actionlint/actionlint','-oneline'],cwd=ROOT,capture_output=True,text=True)
(OUT/'actionlint.log').write_text(lint.stdout+lint.stderr);record('all workflow schemas pass actionlint',lint.returncode==0,exit_code=lint.returncode)
result['utc_end']=datetime.datetime.now(datetime.timezone.utc).isoformat();(OUT/'independent-checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':len(result['checks']),'failed':[c for c in result['checks'] if not c['passed']]},indent=2))
