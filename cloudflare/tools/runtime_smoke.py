"""Run against an isolated local/staging Worker AFTER provisioning its test account.
This script was supplied but not executed against workerd or remote D1 in v24.
"""
import argparse,getpass,sys
from pathlib import Path
from urllib.parse import urlparse
import httpx
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.reporting import FIELDS
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--base-url',required=True);p.add_argument('--origin',required=True);p.add_argument('--email',required=True)
a=p.parse_args()
if urlparse(a.base_url).scheme!='https' and urlparse(a.base_url).hostname not in {'localhost','127.0.0.1'}:p.error('Use HTTPS except for localhost')
password=getpass.getpass('Staging tester password: ')
def checked(r,status=200):
    if r.status_code!=status:raise RuntimeError(f'{r.request.method} {r.request.url.path}: expected {status}, got {r.status_code}: {r.text[:250]}')
    return r
with httpx.Client(base_url=a.base_url.rstrip('/'),headers={'Origin':a.origin},timeout=60) as c:
    checked(c.get('/health'))
    checked(c.post('/auth/login',json={'email':a.email,'password':password}))
    orgs=checked(c.get('/organizations')).json()
    if not orgs:raise RuntimeError('Provision an isolated staging workspace first')
    org=orgs[0]['id'];base='/organizations/'+org+'/reports'
    content='id,label,amount,currency,date,status,received_amount,received_date,last_activity\nM1,Runtime probe,100.00,USD,2026-10-17,won,0,,\n'
    body={'content':content,'mapping':{k:k for k in FIELDS},'name':'M1 runtime smoke'}
    checked(c.post(base+'/preview',json=body))
    sid=checked(c.post(base,json=body),201).json()['id']
    query='?start=2026-10-01&end=2026-10-31&currency=USD'
    try:
        result=checked(c.get(base+'/'+sid+query)).json()
        assert result['summary']['recorded_won']=='100.00'
        checked(c.get(base+'/'+sid+'/export'+query))
        checked(c.post('/auth/logout'));checked(c.get('/auth/me'),401)
        checked(c.post('/auth/login',json={'email':a.email,'password':password}))
        checked(c.get(base+'/'+sid+query))
    finally:checked(c.delete(base+'/'+sid))
print('Runtime smoke passed. Restart the Worker and separately repeat retrieval of a retained snapshot to prove restart persistence.')
