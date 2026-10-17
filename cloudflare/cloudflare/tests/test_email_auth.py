import asyncio
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from src import api, email_auth
from src.reporting import FIELDS

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

REAL_SEND_LINK=email_auth.send_link
ORIGIN='https://staging.example.com'
@pytest.fixture
def setup(tmp_path, monkeypatch):
    binding=Binding(tmp_path/'d1.sqlite')
    with binding.connect() as c:
        for name in ['0001_m1.sql','0002_email_login.sql']:
            c.executescript((Path(__file__).parents[1]/'migrations'/name).read_text())
    env=SimpleNamespace(DB=binding,APP_ENV='staging',FRONTEND_URL=ORIGIN,AUTH_PUBLIC_ORIGIN=ORIGIN,LEGAL_VERSION='test-legal-v1',REGISTRATION_ENABLED='false',MAIL_API_KEY='test-only',MAIL_FROM='test@example.com')
    messages=[]
    async def send(r,email,token):messages.append((email,token))
    async def no_wait(*args):pass
    monkeypatch.setattr(email_auth,'send_link',send)
    monkeypatch.setattr(email_auth.asyncio,'sleep',no_wait)
    def make():return TestClient(EnvApp(env),base_url=ORIGIN,headers={'Origin':ORIGIN})
    return binding,env,messages,make

def seed(setup,email='owner@example.com'):
    binding=setup[0];uid=api.uid()
    with binding.connect() as c:c.execute('INSERT INTO users VALUES (?,?,?,0,?)',(uid,email,'!email-link-only','en'))
    return uid

def login(setup,email='owner@example.com',client=None):
    client=client or setup[3]();r=client.post('/auth/email/request',json={'email':email});assert r.status_code==202,r.text
    token=setup[2][-1][1];r=client.post('/auth/email/confirm',json={'token':token});assert r.status_code==200,r.text
    return client,r.json(),token

def test_existing_login_logout_and_session_flags(setup):
    seed(setup);c,u,t=login(setup)
    assert u['verified'] and c.get('/auth/me').json()['id']==u['id']
    with setup[0].connect() as d:
        assert d.execute('SELECT count(*) FROM sessions').fetchone()[0]==1
        assert d.execute('SELECT token_hash FROM sessions').fetchone()[0]!=c.cookies.get('wazeros_session')
    assert c.post('/auth/logout').status_code==200
    assert c.get('/auth/me').status_code==401

def test_session_cookie_flags(setup):
    seed(setup);c=setup[3]();r=c.post('/auth/email/request',json={'email':'owner@example.com'})
    assert 'Secure' in r.headers['set-cookie'] and 'HttpOnly' in r.headers['set-cookie'] and 'SameSite=strict' in r.headers['set-cookie']
    r=c.post('/auth/email/confirm',json={'token':setup[2][-1][1]})
    cookie=r.headers.get_list('set-cookie')[0]
    assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=lax' in cookie

def test_new_account_requires_consent_and_feature_flag(setup):
    env=setup[1];env.REGISTRATION_ENABLED='true';c=setup[3]()
    assert c.post('/auth/email/request',json={'email':'new@example.com'}).status_code==202
    assert not setup[2]
    r=c.post('/auth/email/request',json={'email':'new@example.com','accept_terms':True,'document_version':env.LEGAL_VERSION})
    assert r.status_code==202
    with setup[0].connect() as d:assert d.execute('SELECT count(*) FROM users').fetchone()[0]==0
    assert c.post('/auth/email/confirm',json={'token':setup[2][-1][1]}).status_code==200
    with setup[0].connect() as d:
        assert d.execute('SELECT password_hash FROM users').fetchone()[0]=='!email-link-only'
        assert d.execute('SELECT count(*) FROM legal_acceptances').fetchone()[0]==1

def test_registration_disabled_unknown_generic(setup):
    seed(setup);c=setup[3]();a=c.post('/auth/email/request',json={'email':'owner@example.com'})
    b=c.post('/auth/email/request',json={'email':'missing@example.com','accept_terms':True,'document_version':setup[1].LEGAL_VERSION})
    assert a.status_code==b.status_code==202 and a.json()==b.json()
    assert len(setup[2])==1

def test_expired_token(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});t=setup[2][-1][1]
    with setup[0].connect() as d:d.execute('UPDATE email_login_challenges SET expires_at=0')
    assert c.post('/auth/email/confirm',json={'token':t}).status_code==400
    assert c.get('/auth/me').status_code==401

def test_replay_and_missing_browser(setup):
    seed(setup);c,u,t=login(setup)
    assert c.post('/auth/email/confirm',json={'token':t}).status_code==400
    assert setup[3]().post('/auth/email/confirm',json={'token':t}).status_code==400

def test_wrong_browser_cannot_consume(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});t=setup[2][-1][1]
    assert setup[3]().post('/auth/email/confirm',json={'token':t}).status_code==400
    assert c.post('/auth/email/confirm',json={'token':t}).status_code==200

def test_new_link_invalidates_old(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});old=setup[2][-1][1]
    c.post('/auth/email/request',json={'email':'owner@example.com'});new=setup[2][-1][1]
    assert c.post('/auth/email/confirm',json={'token':old}).status_code==400
    assert c.post('/auth/email/confirm',json={'token':new}).status_code==200

def test_tokens_stored_hashed(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});t=setup[2][-1][1]
    with setup[0].connect() as d:
        row=d.execute('SELECT * FROM email_login_challenges').fetchone()
        assert row['token_hash']==api.digest(t) and t not in str(dict(row))
        assert row['browser_hash']==api.digest(c.cookies.get(email_auth.BROWSER_COOKIE))

def test_rate_limit(setup):
    c=setup[3]()
    for i in range(5):assert c.post('/auth/email/request',json={'email':'missing@example.com'}).status_code==202
    assert c.post('/auth/email/request',json={'email':'missing@example.com'}).status_code==429

def test_origin_rejection(setup):
    c=setup[3]()
    assert c.post('/auth/email/request',headers={'Origin':'https://evil.example'},json={'email':'owner@example.com'}).status_code==403
    assert c.post('/auth/email/confirm',headers={'Origin':'https://evil.example'},json={'token':'a'*43}).status_code==403

def test_mail_unconfigured(setup):
    setup[1].MAIL_API_KEY=''
    assert setup[3]().post('/auth/email/request',json={'email':'owner@example.com'}).status_code==503

def test_delivery_failure_generic_and_token_removed(setup,monkeypatch):
    seed(setup)
    async def broken(*args):raise RuntimeError('provider failure')
    monkeypatch.setattr(email_auth,'send_link',broken)
    r=setup[3]().post('/auth/email/request',json={'email':'owner@example.com'})
    assert r.status_code==202 and r.json()==email_auth.GENERIC
    with setup[0].connect() as d:assert d.execute('SELECT count(*) FROM email_login_challenges').fetchone()[0]==0

@pytest.mark.parametrize('path',['login','signup','forgot-password','reset-password','verify','resend-verification'])
def test_password_endpoints_disabled(setup,path):
    assert setup[3]().post('/auth/'+path,json={}).status_code==410

@pytest.mark.parametrize('token',['', 'short', 'a'*44, '<'*43])
def test_invalid_tokens(setup,token):
    assert setup[3]().post('/auth/email/confirm',json={'token':token}).status_code==422

def test_get_does_not_consume_and_security_headers(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});t=setup[2][-1][1]
    r=c.get('/auth/email#token='+t)
    assert r.status_code==200 and t not in r.text
    assert r.headers['referrer-policy']=='no-referrer'
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']
    assert c.get('/auth/me').status_code==401
    assert c.post('/auth/email/confirm',json={'token':t}).status_code==200

def test_feature_flag_rechecked_at_confirmation(setup):
    env=setup[1];env.REGISTRATION_ENABLED='true';c=setup[3]()
    c.post('/auth/email/request',json={'email':'new@example.com','accept_terms':True,'document_version':env.LEGAL_VERSION});t=setup[2][-1][1]
    env.REGISTRATION_ENABLED='false'
    assert c.post('/auth/email/confirm',json={'token':t}).status_code==400

def test_concurrent_consumption_one_session(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});t=setup[2][-1][1];browser=c.cookies.get(email_auth.BROWSER_COOKIE)
    def attempt(_):
        client=setup[3]();client.cookies.set(email_auth.BROWSER_COOKIE,browser,path='/auth/email')
        return client.post('/auth/email/confirm',json={'token':t}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:codes=list(pool.map(attempt,range(2)))
    assert sorted(codes)==[200,400]
    with setup[0].connect() as d:assert d.execute('SELECT count(*) FROM sessions').fetchone()[0]==1

def test_atomic_rollback_if_session_insert_fails(setup):
    seed(setup);c=setup[3]();c.post('/auth/email/request',json={'email':'owner@example.com'});t=setup[2][-1][1]
    with setup[0].connect() as d:d.execute("CREATE TRIGGER reject_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'test failure'); END")
    c.raise_server_exceptions=False
    # The adapter uses a real SQLite transaction: verify rollback directly after failed request.
    try:c.post('/auth/email/confirm',json={'token':t})
    except Exception:pass
    with setup[0].connect() as d:
        assert d.execute('SELECT count(*) FROM token_uses').fetchone()[0]==0
        assert d.execute('SELECT count(*) FROM email_login_challenges').fetchone()[0]==1

def test_workspace_reports_isolation_and_restart(setup):
    seed(setup);c,u,t=login(setup)
    r=c.post('/organizations',json={'name':'Test workspace','industry':'clinic','currency':'USD'});assert r.status_code==201,r.text
    org=r.json()['id'];base='/organizations/'+org+'/reports'
    csv='id,label,amount,currency,date,status,received_amount,received_date,last_activity\nA,Example sale,1000.00,USD,2026-09-01,won,500.00,2026-09-02,2026-08-01\n'
    body={'content':csv,'mapping':{k:k for k in FIELDS},'name':'Test snapshot'}
    assert c.post(base,json=body).status_code==402
    with setup[0].connect() as d:d.execute('INSERT INTO entitlements VALUES (?,?,?)',(org,api.now()+3600,'TEST ONLY'))
    assert c.post(base+'/preview',json=body).json()['accepted']==1
    r=c.post(base,json=body);assert r.status_code==201,r.text;sid=r.json()['id']
    query='?start=2026-09-01&end=2026-09-30&currency=USD'
    assert c.get(base+'/'+sid+query).status_code==200
    assert c.get(base+'/'+sid+'/export'+query).status_code==200
    restarted=setup[3]();restarted.cookies.update(c.cookies)
    assert restarted.get(base).json()[0]['id']==sid
    seed(setup,'other@example.com');other,_,_=login(setup,'other@example.com')
    assert other.get(base).status_code==404
    assert other.delete(base+'/'+sid).status_code==404
    assert c.delete(base+'/'+sid).status_code==200

def test_health_and_status(setup):
    c=setup[3]();assert c.get('/health').json()['auth']=='email_link'
    assert c.get('/auth/email/status').json()['version']=='29.0.0'

def test_invalid_public_origin(setup):
    setup[1].AUTH_PUBLIC_ORIGIN='http://insecure.example'
    assert setup[3]().get('/auth/email/status').status_code==503


def test_expired_session_rejected(setup):
    seed(setup);c,_,_=login(setup)
    with setup[0].connect() as d:d.execute('UPDATE sessions SET expires_at=0')
    assert c.get('/auth/me').status_code==401

def test_legal_version_change_rejects_signup(setup):
    setup[1].REGISTRATION_ENABLED='true';c=setup[3]()
    c.post('/auth/email/request',json={'email':'new@example.com','accept_terms':True,'document_version':setup[1].LEGAL_VERSION});t=setup[2][-1][1]
    setup[1].LEGAL_VERSION='changed'
    assert c.post('/auth/email/confirm',json={'token':t}).status_code==400

def test_provider_payload_uses_fragment_and_idempotency(setup,monkeypatch):
    from starlette.requests import Request
    captured=[]
    async def fake(payload,headers):captured.append((payload,headers))
    monkeypatch.setattr(email_auth,'provider_send',fake)
    request=Request({'type':'http','env':setup[1]})
    asyncio.run(REAL_SEND_LINK(request,'owner@example.com','a'*43))
    payload,headers=captured[0]
    assert '/auth/email#token='+'a'*43 in payload['text']
    assert '?token=' not in payload['text']
    assert headers['Idempotency-Key']=='email-login/'+api.digest('a'*43)
    assert payload['to']==['owner@example.com']

def test_global_daily_quota(setup):
    with setup[0].connect() as d:d.execute('INSERT INTO rate_limits VALUES (?,?,?)',(api.digest('email-global-day'),50,api.now()+86400))
    assert setup[3]().post('/auth/email/request',json={'email':'missing@example.com'}).status_code==429

def test_migration_revokes_legacy_sessions(setup):
    uid=seed(setup)
    with setup[0].connect() as d:
        d.execute('INSERT INTO sessions VALUES (?,?,?)',('old-session',uid,api.now()+3600))
        d.execute('INSERT INTO action_tokens VALUES (?,?,?,?)',('old-token',uid,'reset',api.now()+3600))
        d.executescript((Path(__file__).parents[1]/'migrations/0002_email_login.sql').read_text())
        assert d.execute('SELECT count(*) FROM sessions').fetchone()[0]==0
        assert d.execute('SELECT count(*) FROM action_tokens').fetchone()[0]==0

def test_member_cannot_write_reports(setup):
    uid=seed(setup);c,_,_=login(setup)
    org=api.uid()
    with setup[0].connect() as d:
        d.execute('INSERT INTO organizations VALUES (?,?,?,?)',(org,'Member workspace','general','USD'))
        d.execute('INSERT INTO memberships VALUES (?,?,?)',(org,uid,'member'))
        d.execute('INSERT INTO entitlements VALUES (?,?,?)',(org,api.now()+3600,'TEST ONLY'))
    assert c.post('/organizations/'+org+'/reports/preview',json={'content':'','mapping':{},'name':'Test'}).status_code==403
