"""Vigía: aplicación educativa para laboratorio local."""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.demo import seed_demo, CASES
from app.security import password_hash, verify_password, valid_new_password, protect_response
from starlette.concurrency import run_in_threadpool

ROOT = Path(__file__).parent
DATA = Path(os.getenv('DATA_DIR', str(ROOT.parent / 'data')))
LOGS = Path(os.getenv('LOG_DIR', str(ROOT.parent / 'logs')))
SECRET = os.getenv('SESSION_SECRET', '')
SECURE = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
COOKIE_NAME = '__Host-vigia_session' if SECURE else 'vigia_session'
REGISTRATION_OPEN = os.getenv('REGISTRATION_OPEN','true').lower() == 'true'
LIMITS = {'users':50, 'domains':50, 'incidents':200, 'notes':100}
DUMMY_HASH = ''
logger = logging.getLogger('vigia')
os.umask(0o077)

@contextmanager
def db():
    con = sqlite3.connect(DATA / 'vigia.db', timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    try:
        with con:
            yield con
    finally:
        con.close()

def event(request, name, user_id=None, **fields):
    record = {'timestamp': datetime.now(timezone.utc).isoformat(), 'app': 'vigia',
              'event': name, 'srcip': request.client.host if request.client else 'unknown',
              'user_id': user_id, 'request_id':getattr(request.state,'request_id','unknown'), **fields}
    logger.info(json.dumps(record, ensure_ascii=False))

def digest(value):
    return hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()

def migrate_attribution(con):
    """Add nullable attribution without inventing missing historical authors."""
    columns={r['name'] for r in con.execute('PRAGMA table_info(incidents)')}
    if 'created_by' not in columns:
        con.execute('ALTER TABLE incidents ADD COLUMN created_by INTEGER REFERENCES users(id)')
        con.execute("ALTER TABLE incidents ADD COLUMN creation_source TEXT NOT NULL DEFAULT 'legacy'")
        con.execute('ALTER TABLE incidents ADD COLUMN updated_by INTEGER REFERENCES users(id)')
        con.execute('ALTER TABLE incidents ADD COLUMN updated_at TEXT')
    if 'author_id' not in {r['name'] for r in con.execute('PRAGMA table_info(notes)')}:
        con.execute('ALTER TABLE notes ADD COLUMN author_id INTEGER REFERENCES users(id)')
        con.execute("ALTER TABLE notes ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy'")

def username_key(name):
    return unicodedata.normalize('NFKC',name).strip().casefold()

def migrate_accounts(con):
    columns={r['name'] for r in con.execute('PRAGMA table_info(users)')}
    if 'name_key' not in columns:
        con.execute('ALTER TABLE users ADD COLUMN name_key TEXT')
    if 'welcome_seen' not in columns:
        con.execute('ALTER TABLE users ADD COLUMN welcome_seen INTEGER NOT NULL DEFAULT 0')
    if 'role' not in columns:
        con.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if 'active' not in columns:
        con.execute('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1')
    # Preserve IDs and owned data. Resolve legacy duplicate display names explicitly.
    used=set()
    for row in con.execute('SELECT id,name FROM users ORDER BY id').fetchall():
        name=row['name'].strip()
        key=username_key(name)
        if key in used:
            base=name[:40]
            name=base+' #'+str(row['id'])
            while username_key(name) in used: name+='x'
            key=username_key(name)
        used.add(key)
        con.execute('UPDATE users SET name=?,name_key=? WHERE id=?',(name,key,row['id']))
    con.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_unique_name ON users(name_key)')
    if 'role' not in columns:
        con.execute("UPDATE users SET role='admin' WHERE name_key='admin'")

def bootstrap_admin(con):
    """Initial administrator with a unique local password."""
    con.execute('CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    if con.execute("SELECT 1 FROM app_settings WHERE key='admin_initialized'").fetchone(): return
    if con.execute("SELECT 1 FROM users WHERE name_key='admin'").fetchone():
        con.execute("INSERT INTO app_settings VALUES('admin_initialized','1')")
        return
    if con.execute("SELECT 1 FROM users WHERE email='admin@vigia.test'").fetchone():
        raise RuntimeError('El correo admin@vigia.test ya pertenece a otra cuenta. No se sobrescribe.')
    credential=DATA/'admin-inicial.txt'
    password=secrets.token_urlsafe(24)
    # Exclusive creation avoids following symlinks or overwriting an existing secret.
    with open(credential,'x',opener=lambda path,flags: os.open(path,flags,0o600)) as f:
        f.write('Usuario: admin\nCorreo: admin@vigia.test\nContraseña: '+password+'\nCambia la contraseña desde Seguridad de la cuenta y elimina este archivo.\n')
    uid=con.execute("INSERT INTO users(name,email,password,name_key,role) VALUES('admin','admin@vigia.test',?,'admin','admin')",(password_hash(password),)).lastrowid
    con.execute("INSERT INTO app_settings VALUES('admin_initialized','1')")
    print('Cuenta admin creada. Credenciales iniciales en data/admin-inicial.txt (privado).',flush=True)

INCIDENT_SELECT = '''SELECT i.*,d.name AS domain,c.name AS created_by_name,
    e.name AS updated_by_name FROM incidents i
    JOIN domains d ON d.id=i.domain_id
    LEFT JOIN users c ON c.id=i.created_by
    LEFT JOIN users e ON e.id=i.updated_by'''

@asynccontextmanager
async def lifespan(app):
    global DUMMY_HASH
    if len(SECRET) < 32 or len(set(SECRET)) < 12:
        raise RuntimeError('Genera SESSION_SECRET de al menos 32 caracteres en .env')
    DUMMY_HASH = password_hash(secrets.token_urlsafe(32))
    DATA.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOGS / 'events.jsonl', maxBytes=2_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id), csrf TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS domains(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), name TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id,name));
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), domain_id INTEGER REFERENCES domains(id), title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL, priority TEXT NOT NULL, status TEXT DEFAULT 'pendiente', created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, incident_id INTEGER REFERENCES incidents(id), body TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
        ''')
        con.executescript('''
        CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY, count INTEGER NOT NULL, until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS demo_loaded(user_id INTEGER PRIMARY KEY REFERENCES users(id));
        ''')
        migrate_attribution(con)
        if 'demo_key' not in {r['name'] for r in con.execute('PRAGMA table_info(incidents)')}:
            con.execute('ALTER TABLE incidents ADD COLUMN demo_key INTEGER')
            for key,case in enumerate(CASES,1):
                con.execute("UPDATE incidents SET demo_key=? WHERE creation_source='demo' AND title=?",(key,'[DEMO] '+case[1]))
        migrate_accounts(con)
        if 'last_seen' not in [r['name'] for r in con.execute('PRAGMA table_info(sessions)')]:
            con.execute('ALTER TABLE sessions ADD COLUMN last_seen REAL NOT NULL DEFAULT 0')
            con.execute('UPDATE sessions SET last_seen=?', (time.time(),))
        con.executescript('''
        CREATE INDEX IF NOT EXISTS domains_owner ON domains(user_id);
        CREATE INDEX IF NOT EXISTS incidents_owner ON incidents(user_id);
        CREATE INDEX IF NOT EXISTS notes_incident ON notes(incident_id);
        CREATE INDEX IF NOT EXISTS sessions_owner ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS limits_expiry ON limits(until);
        ''')
        bootstrap_admin(con)
        con.execute('DELETE FROM sessions WHERE expires<=? OR last_seen<=?',(time.time(),time.time()-900))
    yield
    logger.removeHandler(handler)
    handler.close()

app = FastAPI(title='Vigía', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

class BodyLimit:
    """Límite real de cuerpo, también para transferencias sin Content-Length."""
    def __init__(self, app, timeout=5):
        self.app=app
        self.timeout=timeout
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        body = bytearray()
        try:
            async with asyncio.timeout(self.timeout):
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect': return
                    chunk=message.get('body', b'')
                    if len(body)+len(chunk)>16384:
                        return await JSONResponse({'detail':'Petición demasiado grande.'},status_code=413)(scope,receive,send)
                    body.extend(chunk)
                    if not message.get('more_body', False): break
        except TimeoutError:
            return await JSONResponse({'detail':'Tiempo de envío agotado.'},status_code=408)(scope,receive,send)
        consumed = False
        async def limited_receive():
            nonlocal consumed
            if not consumed:
                consumed=True
                return {'type':'http.request','body':bytes(body),'more_body':False}
            return await receive()
        await self.app(scope, limited_receive, send)

app.add_middleware(BodyLimit)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv('ALLOWED_HOSTS','localhost,127.0.0.1').split(','))

@app.middleware('http')
async def headers(request, call_next):
    request.state.request_id=secrets.token_hex(8)
    response = None
    if request.url.path.startswith('/api/'):
        try:
            await run_in_threadpool(throttle,request,'','traffic')
        except HTTPException as exc:
            response=JSONResponse({'detail':exc.detail},status_code=exc.status_code,headers=exc.headers)
    if response is None and request.method in ('POST', 'PATCH', 'DELETE', 'PUT'):
        origin = request.headers.get('origin')
        if (origin is not None and origin != str(request.base_url).rstrip('/')) or request.headers.get('sec-fetch-site') == 'cross-site':
            event(request, 'origin_denied')
            response = JSONResponse({'detail':'Origen no permitido.'},status_code=403)
        elif request.headers.get('x-vigia-request') != '1' or request.headers.get('content-type','').split(';')[0] != 'application/json':
            event(request, 'request_denied')
            response = JSONResponse({'detail': 'Petición no permitida.'}, status_code=403)
    if response is None: response = await call_next(request)
    response=protect_response(response,SECURE)
    response.headers['X-Request-ID']=request.state.request_id
    return response

@app.exception_handler(Exception)
async def unexpected(request, exc):
    event(request, 'internal_error', error_type=type(exc).__name__)
    return protect_response(JSONResponse({'detail':'Error interno. Consulta los registros del laboratorio.'},status_code=500),SECURE)

def throttle(request, email, kind):
    now = time.time()
    ip = request.client.host if request.client else 'unknown'
    # Contadores persistentes, transacción atómica y claves sin correos/IP en claro.
    specs = [(kind+':ip:'+ip, {'traffic':120,'login':30,'register':5,'password':10}[kind])]
    period=60 if kind=='traffic' else 300
    if kind in ('login','password'): specs.append((kind+':account:'+email, 8))
    denied = False
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        con.execute('DELETE FROM limits WHERE until<=?',(now,))
        if con.execute('SELECT count(*) FROM limits').fetchone()[0] >= 10000:
            raise HTTPException(503,'Servicio ocupado. Inténtalo más tarde.',headers={'Retry-After':'60'})
        for key, limit in specs:
            key=digest(key)
            row=con.execute('SELECT count FROM limits WHERE key=?',(key,)).fetchone()
            if row and row['count'] >= limit: denied=True
        if not denied:
            for key, limit in specs:
                con.execute('INSERT INTO limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1',(digest(key),now+period))
    if denied:
        event(request,'rate_limited', action=kind)
        raise HTTPException(429,f'Demasiadas peticiones. Espera {period} segundos.',headers={'Retry-After':str(period)})

@app.exception_handler(RequestValidationError)
async def invalid(request, exc):
    event(request, 'validation_failed', error_count=len(exc.errors()))
    return JSONResponse({'detail': 'Revisa los campos: formato, opciones o longitud incorrectos.'}, status_code=422)

def auth(request, write=False):
    with db() as con:
        row = con.execute('SELECT s.*, u.name, u.email, u.welcome_seen, u.role, u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active=1 AND token=? AND expires>? AND last_seen>?', (digest(request.cookies.get(COOKIE_NAME,'')), time.time(),time.time()-900)).fetchone()
    if not row:
        event(request, 'auth_required')
        raise HTTPException(401, 'Inicia sesión para continuar.')
    if write and not hmac.compare_digest(request.headers.get('x-csrf-token',''), row['csrf']):
        event(request, 'csrf_denied', row['user_id'])
        raise HTTPException(403, 'Petición no permitida. Recarga la página.')
    with db() as con: con.execute('UPDATE sessions SET last_seen=? WHERE token=?',(time.time(),row['token']))
    return dict(row)

class InputModel(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)

class Credentials(InputModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    @field_validator('email')
    @classmethod
    def email_valid(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
            raise ValueError('Correo no válido')
        return value

class Registration(Credentials):
    @field_validator('password')
    @classmethod
    def password_policy(cls,value): return valid_new_password(value)
    name: str = Field(min_length=2, max_length=60)
    @field_validator('name')
    @classmethod
    def clean_name(cls, value):
        if len(value.strip()) < 2:
            raise ValueError('Nombre vacío')
        return value.strip()

class Domain(InputModel):
    name: str = Field(min_length=6, max_length=253)
    @field_validator('name')
    @classmethod
    def valid_domain(cls, value):
        value = value.strip().lower()
        # Solo nombres ficticios .test; nunca se resuelven ni escanean.
        labels = value.split('.')
        if labels[-1] != 'test' or len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
            raise ValueError('Usa un dominio ficticio .test')
        return value

class Incident(InputModel):
    domain_id: int = Field(gt=0)
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=5, max_length=3000)
    category: str
    priority: str
    @field_validator('title', 'description')
    @classmethod
    def not_blank(cls, value, info):
        if len(value.strip()) < (3 if info.field_name == 'title' else 5): raise ValueError('Texto vacío')
        return value.strip()
    @field_validator('category')
    @classmethod
    def category_ok(cls, value):
        if value not in ('phishing','acceso','equipo','otro'): raise ValueError('Categoría')
        return value
    @field_validator('priority')
    @classmethod
    def priority_ok(cls, value):
        if value not in ('baja','media','alta'): raise ValueError('Prioridad')
        return value

class Update(InputModel):
    status: str
    @field_validator('status')
    @classmethod
    def valid_status(cls, value):
        if value not in ('pendiente','investigacion','resuelta'): raise ValueError('Estado')
        return value

class Note(InputModel):
    body: str = Field(min_length=1, max_length=2000)
    @field_validator('body')
    @classmethod
    def not_empty(cls, value):
        if not value.strip(): raise ValueError('Nota vacía')
        return value.strip()

class PasswordChange(InputModel):
    current_password: str = Field(min_length=12,max_length=128)
    new_password: str = Field(min_length=15,max_length=128)
    @field_validator('new_password')
    @classmethod
    def policy(cls,value): return valid_new_password(value)


def quota(con, table, owner=None, add=1):
    queries={'users':('SELECT count(*) FROM users',()),
             'domains':('SELECT count(*) FROM domains WHERE user_id=?',(owner,)),
             'incidents':('SELECT count(*) FROM incidents WHERE user_id=?',(owner,)),
             'notes':('SELECT count(*) FROM notes WHERE incident_id=?',(owner,))}
    query,args=queries[table]
    if con.execute(query,args).fetchone()[0]+add > LIMITS[table]:
        raise HTTPException(409,'Límite de datos del laboratorio alcanzado. Consulta al administrador.')

def owned(con, table, ident, user, request):
    queries={'domains':'SELECT * FROM domains WHERE id=? AND user_id=?',
             'incidents':'SELECT * FROM incidents WHERE id=? AND user_id=?'}
    row = con.execute(queries[table], (ident,user)).fetchone()
    if not row:
        event(request, 'access_denied', user, resource=table, resource_id=ident)
        raise HTTPException(404, 'Recurso no disponible.')
    return dict(row)

@app.get('/health')
def health():
    with db() as con: con.execute('SELECT 1').fetchone()
    return {'status': 'ok', 'app': 'vigia'}

@app.get('/api/config')
def config(): return {'registration_open':REGISTRATION_OPEN,'min_password':15}

@app.post('/api/register', status_code=201)
def register(payload: Registration, request: Request):
    if not REGISTRATION_OPEN: raise HTTPException(403,'El registro de cuentas está cerrado.')
    throttle(request,payload.email,'register')
    hashed=password_hash(payload.password)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        if con.execute('SELECT 1 FROM users WHERE email=?',(payload.email,)).fetchone():
            raise HTTPException(409,'Ese correo ya está registrado. Usa otro o inicia sesión.')
        key=username_key(payload.name)
        if con.execute('SELECT 1 FROM users WHERE name_key=?',(key,)).fetchone():
            raise HTTPException(409,'Ese nombre de usuario ya está registrado. Elige otro.')
        quota(con,'users')
        uid=con.execute('INSERT INTO users(name,email,password,name_key) VALUES(?,?,?,?)',(payload.name,payload.email,hashed,key)).lastrowid
        event(request, 'register_processed', uid)
    return {'message':'Cuenta creada. Ya puedes iniciar sesión.'}

@app.post('/api/login')
def login(payload: Credentials, request: Request, response: Response):
    throttle(request,payload.email,'login')
    with db() as con:
        row=con.execute('SELECT * FROM users WHERE email=?',(payload.email,)).fetchone()
    saved=row['password'] if row else DUMMY_HASH
    valid,legacy=verify_password(payload.password,saved)
    if not row or not valid or not row['active']:
        event(request,'login_failed')
        raise HTTPException(401,'Correo o contraseña incorrectos.')
    upgraded=password_hash(payload.password) if legacy else saved
    token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        fresh=con.execute('SELECT password,active FROM users WHERE id=?',(row['id'],)).fetchone()
        if not fresh or not fresh['active'] or fresh['password']!=saved:
            raise HTTPException(401,'Vuelve a iniciar sesión.')
        if legacy:
            con.execute('UPDATE users SET password=? WHERE id=?',(upgraded,row['id']))
        # Una sesión activa por cuenta. Un nuevo acceso revoca la anterior.
        con.execute('DELETE FROM sessions WHERE user_id=? OR expires<=? OR last_seen<=?',(row['id'],time.time(),time.time()-900))
        con.execute('INSERT INTO sessions(token,user_id,csrf,expires,last_seen) VALUES(?,?,?,?,?)',(digest(token),row['id'],csrf,time.time()+3600,time.time()))
    response.set_cookie(COOKIE_NAME,token,httponly=True,secure=SECURE,samesite='strict',max_age=3600,path='/')
    event(request,'login_ok',row['id'])
    return {'name':row['name'],'csrf':csrf,'welcome_seen':bool(row['welcome_seen']),'role':row['role'],'id':row['id']}

@app.post('/api/password')
def change_password(payload: PasswordChange,request: Request,response: Response):
    user=auth(request,True)
    throttle(request,user['email'],'password')
    with db() as con: row=con.execute('SELECT password FROM users WHERE id=?',(user['user_id'],)).fetchone()
    valid,_=verify_password(payload.current_password,row['password'])
    if not valid:
        event(request,'password_change_denied',user['user_id'])
        raise HTTPException(403,'Contraseña actual incorrecta.')
    if payload.current_password==payload.new_password:
        raise HTTPException(422,'La nueva contraseña debe ser distinta.')
    hashed=password_hash(payload.new_password)
    with db() as con:
        changed=con.execute('UPDATE users SET password=? WHERE id=? AND password=?',(hashed,user['user_id'],row['password'])).rowcount
        if not changed: raise HTTPException(409,'La cuenta ha cambiado. Inicia sesión otra vez.')
        con.execute('DELETE FROM sessions WHERE user_id=?',(user['user_id'],))
    response.delete_cookie(COOKIE_NAME,secure=SECURE,httponly=True,samesite='strict')
    event(request,'password_changed',user['user_id'])
    return {'message':'Contraseña actualizada. Inicia sesión otra vez.'}

@app.post('/api/logout-all')
def logout_all(request: Request,response: Response):
    user=auth(request,True)
    with db() as con: con.execute('DELETE FROM sessions WHERE user_id=?',(user['user_id'],))
    response.delete_cookie(COOKIE_NAME,secure=SECURE,httponly=True,samesite='strict')
    event(request,'sessions_revoked',user['user_id'])
    return {'ok':True}

@app.get('/api/me')
def me(request: Request):
    user = auth(request)
    return {'name': user['name'], 'csrf': user['csrf'], 'welcome_seen':bool(user['welcome_seen']),'role':user['role'],'id':user['user_id']}

@app.post('/api/welcome-seen')
def welcome_seen(request: Request):
    user=auth(request,True)
    with db() as con:
        con.execute('UPDATE users SET welcome_seen=1 WHERE id=?',(user['user_id'],))
    return {'ok':True}

@app.post('/api/logout')
def logout(request: Request, response: Response):
    user = auth(request, True)
    with db() as con: con.execute('DELETE FROM sessions WHERE token=?', (user['token'],))
    response.delete_cookie(COOKIE_NAME,secure=SECURE,httponly=True,samesite='strict')
    event(request, 'logout', user['user_id'])
    return {'ok': True}

@app.get('/api/domains')
def domains(request: Request):
    user = auth(request)
    with db() as con: return [dict(r) for r in con.execute('SELECT id,name,created FROM domains WHERE user_id=? ORDER BY id DESC', (user['user_id'],))]

@app.post('/api/domains', status_code=201)
def add_domain(payload: Domain, request: Request):
    user = auth(request, True)
    try:
        with db() as con:
            con.execute('BEGIN IMMEDIATE')
            quota(con,'domains',user['user_id'])
            ident = con.execute('INSERT INTO domains(user_id,name) VALUES(?,?)', (user['user_id'],payload.name)).lastrowid
    except sqlite3.IntegrityError: raise HTTPException(409, 'Ese dominio ya está registrado en tu cuenta.')
    event(request, 'domain_created', user['user_id'], resource_id=ident)
    return {'id': ident}

@app.get('/api/incidents')
def incidents(request: Request):
    user = auth(request)
    with db() as con: return [dict(r) for r in con.execute(INCIDENT_SELECT+' WHERE i.user_id=? ORDER BY i.id DESC', (user['user_id'],))]

@app.post('/api/incidents', status_code=201)
def add_incident(payload: Incident, request: Request):
    user = auth(request, True)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        owned(con,'domains',payload.domain_id,user['user_id'],request)
        quota(con,'incidents',user['user_id'])
        ident = con.execute('INSERT INTO incidents(user_id,domain_id,title,description,category,priority,created_by,creation_source) VALUES(?,?,?,?,?,?,?,?)', (user['user_id'],payload.domain_id,payload.title,payload.description,payload.category,payload.priority,user['user_id'],'user')).lastrowid
    event(request,'incident_created',user['user_id'],resource_id=ident)
    return {'id':ident}

@app.get('/api/incidents/{ident}')
def detail(ident: int, request: Request):
    user = auth(request)
    with db() as con:
        owned(con,'incidents',ident,user['user_id'],request)
        result = dict(con.execute(INCIDENT_SELECT+' WHERE i.id=? AND i.user_id=?',(ident,user['user_id'])).fetchone())
        result['notes'] = [dict(r) for r in con.execute('SELECT n.*,u.name AS author_name FROM notes n LEFT JOIN users u ON u.id=n.author_id WHERE n.incident_id=? ORDER BY n.id', (ident,))]
        return result

@app.patch('/api/incidents/{ident}')
def update(ident: int, payload: Update, request: Request):
    user = auth(request, True)
    with db() as con:
        owned(con,'incidents',ident,user['user_id'],request)
        con.execute('UPDATE incidents SET status=?,updated_by=?,updated_at=? WHERE id=?', (payload.status,user['user_id'],datetime.now(timezone.utc).isoformat(),ident))
    event(request,'incident_updated',user['user_id'],resource_id=ident,status=payload.status)
    return {'ok':True}

@app.post('/api/incidents/{ident}/notes', status_code=201)
def note(ident: int, payload: Note, request: Request):
    user = auth(request, True)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        owned(con,'incidents',ident,user['user_id'],request)
        quota(con,'notes',ident)
        con.execute("INSERT INTO notes(incident_id,body,author_id,source) VALUES(?,?,?,'user')", (ident,payload.body,user['user_id']))
        con.execute('UPDATE incidents SET updated_by=?,updated_at=? WHERE id=?',(user['user_id'],datetime.now(timezone.utc).isoformat(),ident))
    event(request,'note_created',user['user_id'],resource_id=ident)
    return {'ok':True}

class DemoSelection(InputModel):
    case_ids: list[int] = Field(min_length=1,max_length=6)
    @field_validator('case_ids')
    @classmethod
    def valid_cases(cls,values):
        if len(set(values))!=len(values) or any(v<1 or v>len(CASES) for v in values):
            raise ValueError('Selección no válida')
        return values

class DemoRemoval(InputModel):
    incident_ids: list[int] = Field(min_length=1,max_length=200)
    @field_validator('incident_ids')
    @classmethod
    def valid_ids(cls,values):
        if len(set(values))!=len(values) or any(v<1 for v in values): raise ValueError('Selección no válida')
        return values

@app.get('/api/demo')
def demo_catalog(request: Request):
    user=auth(request)
    with db() as con:
        loaded=[dict(r) for r in con.execute("SELECT id,title,demo_key FROM incidents WHERE user_id=? AND creation_source='demo' ORDER BY id",(user['user_id'],))]
    return {'catalog':[{'id':key,'title':case[1],'domain':case[0],'priority':case[3],'loaded':any(r['demo_key']==key for r in loaded)} for key,case in enumerate(CASES,1)],'loaded':loaded}

@app.post('/api/demo')
def demo(payload: DemoSelection,request: Request):
    user=auth(request,True)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        keys=[key for key in payload.case_ids if not con.execute('SELECT 1 FROM incidents WHERE user_id=? AND demo_key=?',(user['user_id'],key)).fetchone()]
        missing={CASES[key-1][0] for key in keys if not con.execute('SELECT 1 FROM domains WHERE user_id=? AND name=?',(user['user_id'],CASES[key-1][0])).fetchone()}
        quota(con,'domains',user['user_id'],len(missing))
        quota(con,'incidents',user['user_id'],len(keys))
        added=seed_demo(con,user['user_id'],keys)
    event(request,'demo_loaded',user['user_id'],simulated=True,added=added)
    return {'added':added,'message':f'{added} casos de ejemplo cargados.' if added else 'Los ejemplos seleccionados ya estaban cargados.'}

@app.delete('/api/demo')
def remove_demo(payload: DemoRemoval,request: Request):
    user=auth(request,True)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        for ident in payload.incident_ids:
            row=owned(con,'incidents',ident,user['user_id'],request)
            if row['creation_source']!='demo': raise HTTPException(409,'Solo se pueden eliminar ejemplos identificados por el sistema.')
        for ident in payload.incident_ids:
            con.execute('DELETE FROM notes WHERE incident_id=?',(ident,))
            con.execute('DELETE FROM incidents WHERE id=? AND user_id=?',(ident,user['user_id']))
    event(request,'demo_removed',user['user_id'],simulated=True,removed=len(payload.incident_ids))
    return {'removed':len(payload.incident_ids),'message':'Ejemplos eliminados. Los dominios se conservan.'}

def require_admin(request,write=False):
    user=auth(request,write)
    if user['role']!='admin':
        event(request,'admin_access_denied',user['user_id'])
        raise HTTPException(403,'Se requiere una cuenta administradora.')
    return user

class AccountAccess(InputModel):
    active: bool

@app.get('/api/admin/summary')
def admin_summary(request: Request):
    require_admin(request)
    with db() as con:
        return {'users':con.execute('SELECT count(*) FROM users').fetchone()[0],
                'active':con.execute('SELECT count(*) FROM users WHERE active=1').fetchone()[0],
                'domains':con.execute('SELECT count(*) FROM domains').fetchone()[0],
                'incidents':con.execute('SELECT count(*) FROM incidents').fetchone()[0]}

@app.get('/api/admin/users')
def admin_users(request: Request):
    require_admin(request)
    with db() as con:
        return [dict(r) for r in con.execute('''SELECT u.id,u.name,u.email,u.role,u.active,
            (SELECT count(*) FROM domains d WHERE d.user_id=u.id) AS domains,
            (SELECT count(*) FROM incidents i WHERE i.user_id=u.id) AS incidents
            FROM users u ORDER BY u.id''')]

@app.patch('/api/admin/users/{ident}')
def admin_access(ident: int,payload: AccountAccess,request: Request):
    user=require_admin(request,True)
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        target=con.execute('SELECT role FROM users WHERE id=?',(ident,)).fetchone()
        if not target: raise HTTPException(404,'Cuenta no disponible.')
        if ident==user['user_id'] or target['role']=='admin':
            raise HTTPException(409,'No puedes desactivar cuentas administradoras desde este panel.')
        con.execute('UPDATE users SET active=? WHERE id=?',(int(payload.active),ident))
        if not payload.active: con.execute('DELETE FROM sessions WHERE user_id=?',(ident,))
    event(request,'admin_account_access',user['user_id'],target_user_id=ident,active=payload.active)
    return {'ok':True}

@app.post('/api/admin/users/{ident}/revoke')
def admin_revoke(ident: int,request: Request):
    user=require_admin(request,True)
    with db() as con:
        target=con.execute('SELECT role FROM users WHERE id=?',(ident,)).fetchone()
        if not target: raise HTTPException(404,'Cuenta no disponible.')
        if target['role']=='admin': raise HTTPException(409,'Usa Seguridad de la cuenta para cerrar tus sesiones.')
        con.execute('DELETE FROM sessions WHERE user_id=?',(ident,))
    event(request,'admin_sessions_revoked',user['user_id'],target_user_id=ident)
    return {'ok':True}

@app.get('/api/admin/incidents')
def admin_incidents(request: Request,offset: int=0):
    require_admin(request)
    if offset<0 or offset>10000: raise HTTPException(422,'Página no válida.')
    with db() as con:
        rows=[dict(r) for r in con.execute(INCIDENT_SELECT+''' ORDER BY i.id DESC LIMIT 50 OFFSET ?''',(offset,))]
        owners={r['id']:r['name'] for r in con.execute('SELECT id,name FROM users')}
        for row in rows: row['owner_name']=owners[row['user_id']]
        return {'items':rows,'total':con.execute('SELECT count(*) FROM incidents').fetchone()[0]}

@app.get('/api/admin/incidents/{ident}')
def admin_detail(ident: int,request: Request):
    user=require_admin(request)
    with db() as con:
        row=con.execute(INCIDENT_SELECT+' WHERE i.id=?',(ident,)).fetchone()
        if not row: raise HTTPException(404,'Incidencia no disponible.')
        result=dict(row)
        result['owner_name']=con.execute('SELECT name FROM users WHERE id=?',(row['user_id'],)).fetchone()[0]
        result['notes']=[dict(r) for r in con.execute('SELECT n.*,u.name AS author_name FROM notes n LEFT JOIN users u ON u.id=n.author_id WHERE n.incident_id=? ORDER BY n.id',(ident,))]
    event(request,'admin_incident_viewed',user['user_id'],resource_id=ident)
    return result

app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')
@app.get('/')
def index(): return FileResponse(ROOT / 'static' / 'index.html')
