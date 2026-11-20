import os, json, secrets, hashlib, hmac, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import psycopg
from psycopg.rows import dict_row

DB=os.environ.get('DATABASE_URL')
if not DB: raise RuntimeError('DATABASE_URL required; configure managed PostgreSQL')
COOKIE='ams_session'
PH=PasswordHasher()
app=FastAPI(title='Best in Class Proposal Studio', docs_url=None, redoc_url=None)
ROOT=Path(__file__).parent
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')

@contextmanager
def conn():
    with psycopg.connect(DB, row_factory=dict_row) as c: yield c

@app.on_event('startup')
def startup():
    with conn() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,body JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())')
        c.execute('CREATE INDEX IF NOT EXISTS proposal_user_idx ON proposals(user_id,updated_at DESC)')
        c.execute('CREATE TABLE IF NOT EXISTS dealer_settings(user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,body JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())')

class Login(BaseModel):
    email:str
    password:str
class Payload(BaseModel):
    body:dict
    name:str=Field(default='Untitled proposal',max_length=180)

attempts={}
def throttle(ip):
    now=time.monotonic(); attempts[ip]=[t for t in attempts.get(ip,[]) if now-t<900]
    if len(attempts[ip])>=8: raise HTTPException(429,'Too many attempts. Try again later.')
    attempts[ip].append(now)

def auth(request:Request):
    token=request.cookies.get(COOKIE,'')
    if not token: raise HTTPException(401,'Sign in required')
    digest=hashlib.sha256(token.encode()).hexdigest()
    with conn() as c:
        row=c.execute('SELECT user_id,csrf FROM sessions WHERE token_hash=%s AND expires_at>NOW()', (digest,)).fetchone()
    if not row: raise HTTPException(401,'Session expired')
    if request.method not in ('GET','HEAD') and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),row['csrf']):
        raise HTTPException(403,'Invalid CSRF token')
    return row

@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
    if os.getenv('COOKIE_SECURE','true').lower()=='true': response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return response

@app.get('/')
def index(request:Request):
    try: auth(request)
    except HTTPException: return FileResponse(ROOT/'static'/'login.html')
    return FileResponse(ROOT/'static'/'studio.html')

@app.post('/api/login')
def login(data:Login,request:Request):
    throttle(request.client.host if request.client else 'unknown')
    with conn() as c: user=c.execute('SELECT * FROM users WHERE email=%s',(data.email.strip().lower(),)).fetchone()
    try:
        if not user: PH.verify(PH.hash('dummy-password'),data.password)
        else: PH.verify(user['password_hash'],data.password)
    except VerifyMismatchError: pass
    else:
        if user:
            token=secrets.token_urlsafe(48); csrf=secrets.token_urlsafe(32)
            with conn() as c: c.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(%s,%s,%s,%s)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],csrf,datetime.now(timezone.utc)+timedelta(days=7)))
            response=JSONResponse({'ok':True,'csrf':csrf})
            response.set_cookie(COOKIE,token,httponly=True,secure=os.getenv('COOKIE_SECURE','true').lower()=='true',samesite='strict',max_age=604800,path='/')
            return response
    raise HTTPException(401,'Invalid credentials')

@app.get('/api/session')
def session(a=Depends(auth)):
    return {'csrf':a['csrf']}

@app.post('/api/logout')
def logout(request:Request,a=Depends(auth)):
    token=request.cookies.get(COOKIE,'')
    with conn() as c:c.execute('DELETE FROM sessions WHERE token_hash=%s',(hashlib.sha256(token.encode()).hexdigest(),))
    r=JSONResponse({'ok':True});r.delete_cookie(COOKIE,path='/');return r

@app.get('/api/proposals')
def proposals(a=Depends(auth)):
    with conn() as c: return c.execute('SELECT id,name,updated_at FROM proposals WHERE user_id=%s ORDER BY updated_at DESC',(a['user_id'],)).fetchall()

@app.get('/api/proposals/{pid}')
def proposal(pid:str,a=Depends(auth)):
    with conn() as c: row=c.execute('SELECT id,name,body,updated_at FROM proposals WHERE user_id=%s AND id=%s',(a['user_id'],pid)).fetchone()
    if not row:raise HTTPException(404,'Proposal not found')
    return row

@app.put('/api/proposals/{pid}')
def save_proposal(pid:str,data:Payload,a=Depends(auth)):
    if len(json.dumps(data.body))>500_000:raise HTTPException(413,'Proposal too large')
    with conn() as c:
        c.execute('INSERT INTO proposals(id,user_id,name,body) VALUES(%s,%s,%s,%s) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,body=EXCLUDED.body,updated_at=NOW() WHERE proposals.user_id=EXCLUDED.user_id',(pid,a['user_id'],data.name,json.dumps(data.body)))
    return {'ok':True,'id':pid}

@app.delete('/api/proposals/{pid}')
def delete_proposal(pid:str,a=Depends(auth)):
    with conn() as c:c.execute('DELETE FROM proposals WHERE id=%s AND user_id=%s',(pid,a['user_id']))
    return {'ok':True}

@app.get('/api/dealer')
def get_dealer(a=Depends(auth)):
    with conn() as c: row=c.execute('SELECT body FROM dealer_settings WHERE user_id=%s',(a['user_id'],)).fetchone()
    return row['body'] if row else {}

@app.put('/api/dealer')
def put_dealer(data:Payload,a=Depends(auth)):
    if len(json.dumps(data.body))>1_000_000:raise HTTPException(413,'Settings too large')
    with conn() as c:c.execute('INSERT INTO dealer_settings(user_id,body) VALUES(%s,%s) ON CONFLICT(user_id) DO UPDATE SET body=EXCLUDED.body,updated_at=NOW()',(a['user_id'],json.dumps(data.body)))
    return {'ok':True}

@app.get('/health')
def health(): return {'ok':True}
