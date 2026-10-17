"""CPython contract tests using a disk-backed SQLite D1-shaped adapter.
These do not establish workerd/Pyodide or remote D1 compatibility.
"""
import json,sqlite3,time
from pathlib import Path
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from src import api
from src.passwords import encode,verify
from src.reporting import FIELDS
PASSWORD='Test-only-password-2026!'
CSV='id,label,amount,currency,date,status,received_amount,received_date,last_activity\nA,Example sale,1000.00,USD,2026-09-01,won,500.00,2026-09-02,2026-08-01\n'
BODY={'content':CSV,'mapping':{k:k for k in FIELDS},'name':'Test snapshot'}
QUERY='?start=2026-09-01&end=2026-09-30&currency=USD'
class Statement:
    def __init__(self,binding,sql,args=()):self.binding=binding;self.sql=sql;self.args=args
    def bind(self,*args):return Statement(self.binding,self.sql,args)
    async def first(self):
        with self.binding.connect() as c:
            row=c.execute(self.sql,self.args).fetchone()
            return dict(row) if row else None
    async def all(self):
        with self.binding.connect() as c:return {'results':[dict(r) for r in c.execute(self.sql,self.args).fetchall()]}
class Binding:
    def __init__(self,path):self.path=path
    def connect(self):
        c=sqlite3.connect(self.path);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c
    def prepare(self,sql):return Statement(self,sql)
    async def batch(self,statements):
        with self.connect() as c:
            for s in statements:c.execute(s.sql,s.args)
        return []
class EnvApp:
    def __init__(self,env):self.env=env
    async def __call__(self,scope,receive,send):
        scope['env']=self.env;await api.app(scope,receive,send)
@pytest.fixture
def setup(tmp_path,monkeypatch):
    binding=Binding(tmp_path/'d1.sqlite')
    with binding.connect() as c:c.executescript((Path(__file__).parents[1]/'migrations/0001_m1.sql').read_text())
    env=SimpleNamespace(DB=binding,APP_ENV='development',FRONTEND_URL='http://localhost:3000',LEGAL_VERSION='2026-10-07',REGISTRATION_ENABLED='true',MAIL_API_KEY='test-only',MAIL_FROM='test@example.com')
    messages=[]
    async def deliver(r,email,token):messages.append((email,token))
    monkeypatch.setattr(api,'deliver',deliver)
    monkeypatch.setattr(api,'deliver_reset',deliver)
    def client():return TestClient(EnvApp(env),headers={'Origin':env.FRONTEND_URL})
    return binding,env,messages,client

def owner(setup,email='owner@example.com',entitled=True):
    binding,env,messages,make=setup;c=make()
    r=c.post('/auth/signup',json={'email':email,'password':PASSWORD,'accept_terms':True,'document_version':env.LEGAL_VERSION});assert r.status_code==201,r.text
    user=r.json();token=messages[-1][1]
    assert c.post('/auth/verify',json={'token':token}).status_code==200
    r=c.post('/organizations',json={'name':'Test workspace','industry':'clinic','currency':'USD'});assert r.status_code==201,r.text
    org=r.json()['id']
    if entitled:
        with binding.connect() as db:db.execute('INSERT INTO entitlements VALUES (?,?,?)',(org,int(time.time())+3600,'TEST ONLY'))
    return c,user,org

def test_full_flow_and_restart(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports'
    assert c.post(base+'/preview',json=BODY).json()['accepted']==1
    r=c.post(base,json=BODY);assert r.status_code==201,r.text;sid=r.json()['id']
    assert c.get(base).json()[0]['rows']==1
    report=c.get(base+'/'+sid+QUERY);assert report.status_code==200,report.text
    assert report.json()['summary']['recorded_won']=='1000.00'
    assert report.json()['summary']['approved_recovered'] is None
    # New binding and ASGI wrapper, same file: no in-process data persistence.
    binding,env,messages,make=setup;env.DB=Binding(binding.path);other=make()
    assert other.post('/auth/login',json={'email':u['email'],'password':PASSWORD}).status_code==200
    assert other.get(base+'/'+sid+QUERY).json()['rows'][0]['id']=='A'
    assert other.get(base+'/'+sid+'/export'+QUERY).status_code==200
    assert other.delete(base+'/'+sid).status_code==200
    assert other.get(base+'/'+sid+QUERY).status_code==404

@pytest.mark.parametrize('operation',['list','read','export','delete','save','preview'])
def test_cross_workspace_denied(setup,operation):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports';sid=c.post(base,json=BODY).json()['id']
    other,_,_=owner(setup,'other@example.com')
    responses={'list':lambda:other.get(base),'read':lambda:other.get(base+'/'+sid+QUERY),'export':lambda:other.get(base+'/'+sid+'/export'+QUERY),'delete':lambda:other.delete(base+'/'+sid),'save':lambda:other.post(base,json=BODY),'preview':lambda:other.post(base+'/preview',json=BODY)}
    assert responses[operation]().status_code==404

def test_snapshot_id_scoped_to_org(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports';sid=c.post(base,json=BODY).json()['id']
    other,_,other_org=owner(setup,'other@example.com')
    assert other.get('/organizations/'+other_org+'/reports/'+sid+QUERY).status_code==404

def test_expired_session(setup):
    c,u,org=owner(setup)
    with setup[0].connect() as db:db.execute('UPDATE sessions SET expires_at=0')
    assert c.get('/organizations/'+org+'/reports').status_code==401

def test_logout_revokes_session(setup):
    c,u,org=owner(setup);token=c.cookies.get('wazeros_session')
    assert c.post('/auth/logout').status_code==200
    c.cookies.set('wazeros_session',token)
    assert c.get('/auth/me').status_code==401

def test_unverified_cannot_create_workspace(setup):
    c=setup[3]();c.post('/auth/signup',json={'email':'new@example.com','password':PASSWORD,'accept_terms':True,'document_version':setup[1].LEGAL_VERSION})
    assert c.post('/organizations',json={'name':'Blocked workspace'}).status_code==403

def test_verification_token_single_use(setup):
    c,u,org=owner(setup)
    assert c.post('/auth/verify',json={'token':setup[2][-1][1]}).status_code==400

def test_expired_verification(setup):
    c=setup[3]();c.post('/auth/signup',json={'email':'new@example.com','password':PASSWORD,'accept_terms':True,'document_version':setup[1].LEGAL_VERSION})
    with setup[0].connect() as db:db.execute('UPDATE action_tokens SET expires_at=0')
    assert c.post('/auth/verify',json={'token':setup[2][-1][1]}).status_code==400
    assert c.get('/auth/me').json()['verified'] is False

def test_invalid_import_no_partial_save(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports'
    bad={**BODY,'content':CSV.replace('1000.00','NaN')}
    assert c.post(base,json=bad).status_code==422
    assert c.get(base).json()==[]

def test_partial_rejection_requires_acceptance(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports'
    body={**BODY,'content':CSV+'B,Bad,NaN,USD,2026-09-01,won,0,,\n'}
    assert c.post(base,json=body).status_code==422
    assert c.get(base).json()==[]
    assert c.post(base,json={**body,'accept_rejected':True}).json()['rejected']==1

def test_entitlement_required(setup):
    c,u,org=owner(setup,entitled=False)
    assert c.get('/organizations/'+org+'/reports').status_code==402

def test_member_read_only(setup):
    c,u,org=owner(setup)
    with setup[0].connect() as db:db.execute("UPDATE memberships SET role='member'")
    assert c.get('/organizations/'+org+'/reports').status_code==200
    assert c.post('/organizations/'+org+'/reports',json=BODY).status_code==403

def test_origin_and_cors(setup):
    c,u,org=owner(setup)
    assert c.post('/auth/logout',headers={'Origin':'https://evil.example'}).status_code==403
    r=c.options('/auth/login',headers={'Access-Control-Request-Method':'POST'})
    assert r.status_code==204 and r.headers['access-control-allow-credentials']=='true'
    assert c.get('/auth/me').headers['cache-control']=='no-store'

def test_registration_closed_by_default(setup):
    setup[1].REGISTRATION_ENABLED='false'
    assert setup[3]().post('/auth/signup',json={'email':'new@example.com','password':PASSWORD,'accept_terms':True,'document_version':setup[1].LEGAL_VERSION}).status_code==503

def test_deployed_requires_https(setup):
    setup[1].APP_ENV='staging'
    assert setup[3]().get('/health').status_code==503

def test_secure_cookie(setup):
    c,u,org=owner(setup);setup[1].APP_ENV='staging';setup[1].FRONTEND_URL='https://app.example.com'
    r=c.post('/auth/login',headers={'Origin':setup[1].FRONTEND_URL},json={'email':u['email'],'password':PASSWORD})
    assert r.status_code==200
    assert all(x in r.headers['set-cookie'].lower() for x in ['secure','httponly','samesite=lax'])

def test_rate_limit(setup):
    c=setup[3]()
    for i in range(10):assert c.post('/auth/login',json={'email':'missing@example.com','password':PASSWORD}).status_code==401
    assert c.post('/auth/login',json={'email':'missing@example.com','password':PASSWORD}).status_code==429

def test_atomic_batch_rollback(setup):
    import asyncio
    binding=setup[0]
    with pytest.raises(sqlite3.IntegrityError):asyncio.run(binding.batch([binding.prepare("INSERT INTO organizations VALUES ('x','Example','general','USD')"),binding.prepare("INSERT INTO memberships VALUES ('x','missing-user','owner')")]))
    with binding.connect() as db:assert db.execute("SELECT * FROM organizations WHERE id='x'").fetchone() is None

def test_snapshot_cap(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports'
    with setup[0].connect() as db:
        for i in range(50):db.execute('INSERT INTO snapshots VALUES (?,?,?,?,?)',(str(i),org,'Snapshot',json.dumps({'rows':[]}),api.stamp()))
    assert c.post(base,json=BODY).status_code==409
    assert len(c.get(base).json())==50

def test_password_format_and_legacy_rejection():
    hashed=encode(PASSWORD)
    assert verify(hashed,PASSWORD) and not verify(hashed,'wrong-password')
    assert not verify('$argon2id$legacy',PASSWORD)

def test_invalid_window(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports';sid=c.post(base,json=BODY).json()['id']
    assert c.get(base+'/'+sid+'?start=2026-10-01&end=2026-09-01').status_code==422

def test_pdf_explicitly_not_ported(setup):
    c,u,org=owner(setup);base='/organizations/'+org+'/reports';sid=c.post(base,json=BODY).json()['id']
    assert c.get(base+'/'+sid+'/export'+QUERY+'&format=pdf').status_code==501

def test_password_reset_revokes_sessions_and_single_use(setup):
    c,u,org=owner(setup)
    assert c.post('/auth/forgot-password',json={'email':u['email']}).status_code==200
    token=setup[2][-1][1];new='New-test-password-2026!'
    assert c.post('/auth/reset-password',json={'token':token,'password':new}).status_code==200
    assert c.get('/auth/me').status_code==401
    assert c.post('/auth/reset-password',json={'token':token,'password':PASSWORD}).status_code==400
    assert c.post('/auth/login',json={'email':u['email'],'password':PASSWORD}).status_code==401
    assert c.post('/auth/login',json={'email':u['email'],'password':new}).status_code==200

def test_expired_reset_does_not_change_password(setup):
    c,u,org=owner(setup)
    c.post('/auth/forgot-password',json={'email':u['email']});token=setup[2][-1][1]
    with setup[0].connect() as db:db.execute("UPDATE action_tokens SET expires_at=0 WHERE purpose='reset'")
    assert c.post('/auth/reset-password',json={'token':token,'password':'New-test-password-2026!'}).status_code==400
    assert c.post('/auth/login',json={'email':u['email'],'password':PASSWORD}).status_code==200

def test_body_limit(setup):
    assert setup[3]().post('/auth/login',content='x'*2_100_001).status_code==413

def test_no_email_config_blocks_signup_without_account(setup):
    setup[1].MAIL_API_KEY=''
    c=setup[3]();assert c.post('/auth/signup',json={'email':'new@example.com','password':PASSWORD,'accept_terms':True,'document_version':setup[1].LEGAL_VERSION}).status_code==503
    with setup[0].connect() as db:assert db.execute('SELECT count(*) FROM users').fetchone()[0]==0
