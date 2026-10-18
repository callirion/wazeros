import traceback
import csv,hashlib,io,json,logging,secrets,time,uuid
from datetime import date,datetime,timezone
from fastapi import FastAPI,HTTPException,Request,Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel,Field
from .store import Store
from .schemas import Signup,Credentials,WorkspaceInput,TokenRequest,EmailRequest,ResetRequest
from .reporting import parse_csv,summarize,safe_cell,FIELDS
app=FastAPI(title='Wazeros Cloudflare M1',version='29.0.0')
def now():return int(time.time())
def stamp():return datetime.now(timezone.utc).isoformat()
def uid():return str(uuid.uuid4())
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def setting(r,k,default=''):return str(getattr(r.scope['env'],k,default))
def db(r):return Store(r.scope['env'].DB)
def audit(actor,action,org=None):return ('INSERT INTO audit_events VALUES (?,?,?,?,?)',(uid(),org,actor,action,stamp()))
def user_data(u):return {k:u[k] for k in ('id','email','locale')}|{'verified':bool(u['verified']),'display_name':'','avatar':''}
def cookie(r,response,token):response.set_cookie('wazeros_session',token,httponly=True,secure=setting(r,'APP_ENV')!='development',samesite='lax',max_age=604800,path='/')
@app.middleware('http')
async def boundary(r,call_next):
    origin=setting(r,'FRONTEND_URL','http://localhost:3000').rstrip('/');supplied=r.headers.get('origin')
    if setting(r,'APP_ENV')!='development' and not origin.startswith('https://'):
        return JSONResponse({'error':{'code':'configuration_error','message':'HTTPS frontend required'}},status_code=503)
    if r.method=='OPTIONS':response=Response(status_code=204 if supplied==origin else 403)
    elif r.method not in {'GET','HEAD'} and supplied!=origin:
        response=JSONResponse({'error':{'code':'origin_rejected','message':'Request origin rejected'}},status_code=403)
    else:
        data=bytearray()
        async for chunk in r.stream():
            data.extend(chunk)
            if len(data)>2_100_000:return JSONResponse({'error':{'code':'body_too_large','message':'Request too large'}},status_code=413)
        r._body=bytes(data);response=await call_next(r)
    if supplied==origin:response.headers.update({'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true','Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type','Vary':'Origin'})
    response.headers.update({'X-Request-ID':uid(),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    return response
@app.exception_handler(HTTPException)
async def known(r,e):return JSONResponse({'error':{'code':str(e.status_code),'message':e.detail}},status_code=e.status_code)
@app.exception_handler(RequestValidationError)
async def invalid(r,e):return JSONResponse({'error':{'code':'validation_error','message':'Invalid request fields'}},status_code=422)
@app.exception_handler(Exception)
async def unknown(r, e):
    frames = " -> ".join(
        f"{frame.filename.rsplit('/', 1)[-1]}:{frame.lineno}:{frame.name}"
        for frame in traceback.extract_tb(e.__traceback__)
    )
    logging.getLogger("wazeros.m1").error(
        "Unhandled error type=%s attribute=%s path=%s frames=%s",
        type(e).__name__, getattr(e, "name", None), r.url.path, frames,
    )
    return JSONResponse(
        {"error": {"code": "internal_error", "message": "Unable to complete request"}},
        status_code=500,
    )

async def throttle(store,key):
    row=await store.first('INSERT INTO rate_limits VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN reset_at<=? THEN 1 ELSE count+1 END,reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END RETURNING count',digest(key),now()+900,now(),now())
    if row['count']>10:raise HTTPException(429,'Too many attempts. Try again later.')
async def actor(r):
    token=r.cookies.get('wazeros_session','')
    u=await db(r).first('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?',digest(token),now()) if token else None
    if not u:raise HTTPException(401,'Authentication required')
    return u
async def access(r,org,write=False,product=False):
    u=await actor(r);s=db(r)
    o=await s.first('SELECT o.*,m.role FROM organizations o JOIN memberships m ON m.org_id=o.id WHERE o.id=? AND m.user_id=?',org,u['id'])
    if not o:raise HTTPException(404,'Workspace not found')
    if write and o['role'] not in {'owner','admin'}:raise HTTPException(403,'Permission denied')
    if product and not await s.first('SELECT org_id FROM entitlements WHERE org_id=? AND expires_at>?',org,now()):raise HTTPException(402,'Active product access required')
    return u,o
def mail_ready(r):return bool(setting(r,'MAIL_API_KEY') and setting(r,'MAIL_FROM'))
@app.get('/health')
async def health(request:Request):
    await db(request).first('SELECT 1 AS ok');return {'status':'ok','phase':'M1','storage':'D1','version':'29.0.0','auth':'email_link'}
@app.get('/auth/delivery-status')
async def delivery_status(request:Request):return {'available':mail_ready(request),'mode':'resend' if mail_ready(request) else 'unconfigured'}
@app.post('/auth/logout')
async def logout(request:Request,response:Response):
    await db(request).batch([('DELETE FROM sessions WHERE token_hash=?',(digest(request.cookies.get('wazeros_session','')),))])
    response.delete_cookie('wazeros_session',path='/')
    return {'ok':True}
@app.get('/auth/me')
async def me(request:Request):return user_data(await actor(request))

@app.get('/organizations')
async def organizations(request:Request):
    u=await actor(request);return await db(request).all('SELECT o.*,m.role FROM organizations o JOIN memberships m ON m.org_id=o.id WHERE m.user_id=?',u['id'])
@app.post('/organizations',status_code=201)
async def create_org(body:WorkspaceInput,request:Request):
    u=await actor(request)
    if not u['verified']:raise HTTPException(403,'Verify your email before creating a workspace')
    org=uid();await db(request).batch([('INSERT INTO organizations VALUES (?,?,?,?)',(org,body.name,body.industry,body.currency)),('INSERT INTO memberships VALUES (?,?,?)',(org,u['id'],'owner')),audit(u['id'],'workspace.created',org)])
    return {'id':org,**body.model_dump(),'role':'owner'}
@app.get('/organizations/{org}')
async def get_org(org:str,request:Request):return (await access(request,org))[1]
@app.get('/organizations/{org}/access')
async def product_access(org:str,request:Request):
    await access(request,org);active=await db(request).first('SELECT org_id FROM entitlements WHERE org_id=? AND expires_at>?',org,now())
    return {'active':bool(active),'checkout_available':False,'trial_active':False}
class CsvInput(BaseModel):
    content:str=Field(max_length=2_000_000)
    mapping:dict[str,str]=Field(default_factory=dict,max_length=12)
    name:str=Field(default='CSV snapshot',min_length=2,max_length=120)
    accept_rejected:bool=False
@app.post('/organizations/{org}/reports/preview')
async def preview(org:str,body:CsvInput,request:Request):
    await access(request,org,True,True);return parse_csv(body.content,body.mapping)
@app.post('/organizations/{org}/reports',status_code=201)
async def save_report(org:str,body:CsvInput,request:Request):
    u,_=await access(request,org,True,True);s=db(request);await throttle(s,'import:'+u['id'])
    if not body.mapping:raise HTTPException(422,'Map required columns first')
    if len(body.name.strip())<2:raise HTTPException(422,'Report name is too short')
    parsed=parse_csv(body.content,body.mapping)
    if not parsed['rows']:raise HTTPException(422,'No valid rows')
    if parsed['errors'] and not body.accept_rejected:raise HTTPException(422,'Explicitly accept rejected rows before saving')
    sid=uid();data=json.dumps({'rows':parsed['rows'],'errors':parsed['errors'],'source':'csv_snapshot'})
    if len(data.encode())>1_500_000:raise HTTPException(413,'Snapshot too large; split the CSV')
    try:await s.batch([('INSERT INTO snapshots VALUES (?,?,?,?,?)',(sid,org,body.name.strip(),data,stamp())),audit(u['id'],'report.imported',org)])
    except Exception as e:
        if 'snapshot_limit' in str(e):raise HTTPException(409,'50 snapshots maximum; delete an old snapshot')
        raise
    return {'id':sid,'name':body.name.strip(),'accepted':len(parsed['rows']),'rejected':len(parsed['errors'])}
@app.get('/organizations/{org}/reports')
async def reports(org:str,request:Request):
    await access(request,org,product=True)
    return await db(request).all("SELECT id,name,created_at,json_array_length(data,'$.rows') AS rows FROM snapshots WHERE org_id=? ORDER BY created_at DESC",org)
async def report_data(r,org,sid,start,end,currency):
    await access(r,org,product=True)
    if currency not in {'USD','EUR','GBP','MAD','CAD','AUD','JPY','CHF','AED','SAR'} or start>end:raise HTTPException(422,'Invalid report window or currency')
    row=await db(r).first('SELECT data FROM snapshots WHERE id=? AND org_id=?',sid,org)
    if not row:raise HTTPException(404,'Snapshot not found')
    rows=json.loads(row['data'])['rows'];summary=summarize(rows,start,end,currency,[])
    summary.update(approved_recovered=None,approved_fee=None,recovery_percentage=None)
    selected=[x for x in rows if x['currency']==currency and (start.isoformat()<=x['date']<=end.isoformat() or x.get('received_date') and start.isoformat()<=x['received_date']<=end.isoformat())]
    return {'summary':summary,'rows':selected,'source':'csv_snapshot','generated_at':stamp(),'claims':[]}
@app.get('/organizations/{org}/reports/{sid}')
async def report(org:str,sid:str,request:Request,start:date,end:date,currency:str='USD'):return await report_data(request,org,sid,start,end,currency)
@app.get('/organizations/{org}/reports/{sid}/export')
async def export(org:str,sid:str,request:Request,start:date,end:date,currency:str='USD',format:str='csv'):
    data=await report_data(request,org,sid,start,end,currency)
    if format!='csv':raise HTTPException(501,'PDF export is not yet ported to M1; use CSV')
    out=io.StringIO();writer=csv.writer(out);writer.writerow(FIELDS)
    for row in data['rows']:writer.writerow([safe_cell(str(row.get(k,''))) for k in FIELDS])
    return Response(out.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="wazeros-report.csv"'})
@app.delete('/organizations/{org}/reports/{sid}')
async def delete_report(org:str,sid:str,request:Request):
    u,_=await access(request,org,True,True);s=db(request)
    if not await s.first('SELECT id FROM snapshots WHERE id=? AND org_id=?',sid,org):raise HTTPException(404,'Snapshot not found')
    await s.batch([('DELETE FROM snapshots WHERE id=? AND org_id=?',(sid,org)),audit(u['id'],'report.deleted',org)]);return {'ok':True}

from .email_auth import router as email_auth_router
app.include_router(email_auth_router)
