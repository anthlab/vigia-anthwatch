import json
import os
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

TMP = tempfile.TemporaryDirectory()
os.environ.update(DATA_DIR=TMP.name+'/data', LOG_DIR=TMP.name+'/logs', SESSION_SECRET='test-only-secret-not-for-deployment-123456789', ALLOWED_HOSTS='localhost,127.0.0.1,testserver')
from app.main import app, password_hash, db

class VigiaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()
    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None,None,None)
        TMP.cleanup()
    def setUp(self):
        self.client.cookies.clear()
        with db() as con:
            for table in ['limits','demo_loaded','notes','incidents','domains','sessions','users']:
                con.execute('DELETE FROM '+table)
        self.h={'X-Vigia-Request':'1'}
    def account(self, email='ana@lab.test'):
        r=self.client.post('/api/register',json={'name':'Ana' if email=='ana@lab.test' else email.split('@')[0],'email':email,'password':'Una-clave-ficticia-123'},headers=self.h)
        self.assertEqual(r.status_code,201)
        r=self.client.post('/api/login',json={'email':email,'password':'Una-clave-ficticia-123'},headers=self.h)
        self.assertEqual(r.status_code,200)
        self.h['X-CSRF-Token']=r.json()['csrf']
        # Los tests históricos usan cuentas sin casos para aislar su escenario.
        with db() as con:
            uid=con.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()[0]
            con.execute('DELETE FROM notes WHERE incident_id IN (SELECT id FROM incidents WHERE user_id=?)',(uid,))
            con.execute('DELETE FROM incidents WHERE user_id=?',(uid,))
            con.execute('DELETE FROM domains WHERE user_id=?',(uid,))
            con.execute('DELETE FROM demo_loaded WHERE user_id=?',(uid,))
    def domain(self):
        r=self.client.post('/api/domains',json={'name':'empresa.test'},headers=self.h)
        self.assertEqual(r.status_code,201)
        return r.json()['id']
    def incident(self,d):
        r=self.client.post('/api/incidents',json={'domain_id':d,'title':'Correo sospechoso','description':'Un correo de prueba ficticio.','category':'phishing','priority':'alta'},headers=self.h)
        self.assertEqual(r.status_code,201)
        return r.json()['id']
    def test_workflow_and_session_revocation(self):
        self.account(); d=self.domain(); i=self.incident(d)
        self.assertEqual(self.client.post(f'/api/incidents/{i}/notes',json={'body':'Verificado en laboratorio'},headers=self.h).status_code,201)
        self.assertEqual(self.client.patch(f'/api/incidents/{i}',json={'status':'resuelta'},headers=self.h).status_code,200)
        self.assertEqual(self.client.get(f'/api/incidents/{i}').json()['status'],'resuelta')
        old=self.client.cookies.get('vigia_session')
        self.assertEqual(self.client.post('/api/logout',json={},headers=self.h).status_code,200)
        self.client.cookies.set('vigia_session',old)
        self.assertEqual(self.client.get('/api/incidents').status_code,401)
    def test_cross_user_isolation(self):
        self.account(); d=self.domain(); i=self.incident(d)
        self.client.cookies.clear(); self.account('bea@lab.test')
        self.assertEqual(self.client.get('/api/domains').json(),[])
        self.assertEqual(self.client.get('/api/incidents').json(),[])
        self.assertEqual(self.client.get(f'/api/incidents/{i}').status_code,404)
        self.assertEqual(self.client.patch(f'/api/incidents/{i}',json={'status':'resuelta'},headers=self.h).status_code,404)
        self.assertEqual(self.client.post(f'/api/incidents/{i}/notes',json={'body':'Nota ajena'},headers=self.h).status_code,404)
        self.assertEqual(self.client.post('/api/incidents',json={'domain_id':d,'title':'Ajena','description':'No permitido','category':'otro','priority':'baja'},headers=self.h).status_code,404)
    def test_invalid_inputs(self):
        self.account()
        for value in ['','https://empresa.test','empresa.com','a..test','-empresa.test','x'*64+'.test']:
            self.assertEqual(self.client.post('/api/domains',json={'name':value},headers=self.h).status_code,422)
        d=self.domain()
        self.assertEqual(self.client.post('/api/domains',json={'name':'empresa.test'},headers=self.h).status_code,409)
        self.assertEqual(self.client.post('/api/incidents',json={'domain_id':d,'title':' '*5,'description':'Prueba','category':'otro','priority':'baja'},headers=self.h).status_code,422)
    def test_csrf_and_unauthenticated(self):
        self.assertEqual(self.client.get('/api/domains').status_code,401)
        self.account()
        self.assertEqual(self.client.post('/api/domains',json={'name':'empresa.test'}).status_code,403)
        self.assertEqual(self.client.post('/api/domains',json={'name':'empresa.test'},headers={'X-Vigia-Request':'1'}).status_code,403)
    def test_passwords_cookies_and_headers(self):
        self.account()
        with db() as con:
            stored=con.execute('SELECT password FROM users').fetchone()[0]
            self.assertNotIn('Una-clave',stored)
            self.assertTrue(stored.startswith('scrypt$131072$8$1$'))
        r=self.client.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h)
        self.assertIn('HttpOnly',r.headers['set-cookie'])
        self.assertIn('SameSite=strict',r.headers['set-cookie'])
        self.assertIn("script-src 'self'",self.client.get('/').headers['content-security-policy'])
    def test_logs_have_no_secrets(self):
        self.account(); self.domain()
        lines=Path(TMP.name+'/logs/events.jsonl').read_text()
        self.assertNotIn('Una-clave-ficticia-123',lines)
        self.assertNotIn(self.client.cookies.get('vigia_session'),lines)
        self.assertNotIn(self.h['X-CSRF-Token'],lines)
        events=[json.loads(line) for line in lines.splitlines()]
        self.assertTrue(any(e['event']=='domain_created' for e in events))
    def test_text_and_sql_are_data(self):
        self.account(); d=self.domain(); i=self.incident(d)
        text="<script>alert(1)</script> ' OR 1=1 --"
        self.assertEqual(self.client.post(f'/api/incidents/{i}/notes',json={'body':text},headers=self.h).status_code,201)
        self.assertEqual(self.client.get(f'/api/incidents/{i}').json()['notes'][0]['body'],text)
        self.assertEqual(len(self.client.get('/api/incidents').json()),1)
    def test_persistence_on_restart(self):
        self.account(); self.domain()
        with TestClient(app) as second:
            second.cookies.update(self.client.cookies)
            self.assertEqual(second.get('/api/domains').json()[0]['name'],'empresa.test')
            self.assertEqual(second.get('/health').json()['status'],'ok')

    def test_demo_idempotent_and_owned(self):
        self.account()
        self.domain()  # dominio preexistente: se reutiliza sin borrarlo
        r=self.client.post('/api/demo',json={'case_ids':[1,2,3,4,5,6]},headers=self.h)
        self.assertEqual(r.json()['added'],6)
        self.assertEqual(len(self.client.get('/api/domains').json()),3)
        cases=self.client.get('/api/incidents').json()
        self.assertEqual(len(cases),6)
        self.assertEqual({c['status'] for c in cases},{'pendiente','investigacion','resuelta'})
        self.assertTrue(all(c['title'].startswith('[DEMO]') for c in cases))
        self.assertEqual(self.client.post('/api/demo',json={'case_ids':[1,2,3,4,5,6]},headers=self.h).json()['added'],0)
        self.assertEqual(len(self.client.get('/api/incidents').json()),6)
        self.client.cookies.clear()
        self.account('otra@lab.test')
        self.assertEqual(self.client.get('/api/incidents/'+str(cases[0]['id'])).status_code,404)

    def test_registration_starts_empty(self):
        r=self.client.post('/api/register',json={'name':'Demo','email':'demo@lab.test','password':'Clave-ficticia-123'},headers=self.h)
        self.assertEqual(r.status_code,201)
        with db() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM incidents').fetchone()[0],0)
            self.assertEqual(con.execute('SELECT count(*) FROM domains').fetchone()[0],0)
            self.assertEqual(con.execute('SELECT count(*) FROM demo_loaded').fetchone()[0],0)

    def test_rate_limit_persists_and_expires(self):
        from unittest.mock import patch
        import time
        self.account()
        # No se realiza fuerza bruta: se prepara directamente el contador de prueba.
        from app.main import digest
        with db() as con:
            con.execute('INSERT OR REPLACE INTO limits VALUES(?,8,?)',(digest('login:account:ana@lab.test'),time.time()+300))
        r=self.client.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h)
        self.assertEqual(r.status_code,429)
        self.assertEqual(r.headers['retry-after'],'300')
        with db() as con: con.execute('UPDATE limits SET until=0')
        self.assertEqual(self.client.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h).status_code,200)

    def test_idle_and_absolute_expiry(self):
        import time
        self.account()
        with db() as con: con.execute('UPDATE sessions SET last_seen=?',(time.time()-901,))
        self.assertEqual(self.client.get('/api/me').status_code,401)
        with db() as con: con.execute('UPDATE sessions SET last_seen=?,expires=0',(time.time(),))
        self.assertEqual(self.client.get('/api/me').status_code,401)

    def test_host_origin_and_body_size(self):
        self.assertEqual(self.client.get('/health',headers={'host':'evil.test'}).status_code,400)
        self.account()
        for origin in ['http://evil.test','null']:
            self.assertEqual(self.client.post('/api/domains',json={'name':'nuevo.test'},headers={**self.h,'Origin':origin}).status_code,403)
        self.assertEqual(self.client.post('/api/domains',content='x'*17000,headers={**self.h,'Content-Type':'application/json'}).status_code,413)
        self.assertEqual(self.client.post('/api/domains',json={'name':'nuevo.test','user_id':99},headers=self.h).status_code,422)
        self.assertEqual(self.client.post('/api/domains',json={'name':'nuevo.test'},headers={**self.h,'Origin':'http://testserver'}).status_code,201)

    def test_password_change_revokes_and_checks_current(self):
        self.account()
        old=self.client.cookies.get('vigia_session')
        payload={'current_password':'Incorrecta-pero-larga','new_password':'Una-frase-nueva-segura-456'}
        self.assertEqual(self.client.post('/api/password',json=payload,headers=self.h).status_code,403)
        payload['current_password']='Una-clave-ficticia-123'
        self.assertEqual(self.client.post('/api/password',json=payload,headers={'X-Vigia-Request':'1'}).status_code,403)
        self.assertEqual(self.client.post('/api/password',json=payload,headers=self.h).status_code,200)
        self.client.cookies.set('vigia_session',old)
        self.assertEqual(self.client.get('/api/me').status_code,401)
        self.assertEqual(self.client.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h).status_code,401)
        self.assertEqual(self.client.post('/api/login',json={'email':'ana@lab.test','password':payload['new_password']},headers=self.h).status_code,200)

    def test_new_login_and_logout_all_revoke(self):
        self.account()
        old=self.client.cookies.get('vigia_session')
        r=self.client.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h)
        new=self.client.cookies.get('vigia_session')
        self.assertNotEqual(old,new)
        self.client.cookies.clear();self.client.cookies.set('vigia_session',old)
        self.assertEqual(self.client.get('/api/me').status_code,401)
        self.client.cookies.clear();self.client.cookies.set('vigia_session',new)
        self.h['X-CSRF-Token']=r.json()['csrf']
        self.assertEqual(self.client.post('/api/logout-all',json={},headers=self.h).status_code,200)
        self.client.cookies.set('vigia_session',new)
        self.assertEqual(self.client.get('/api/me').status_code,401)

    def test_legacy_hash_upgrades_without_data_loss(self):
        import hashlib
        self.account();d=self.domain()
        salt='ab'*16
        old=salt+':'+hashlib.scrypt(b'Una-clave-ficticia-123',salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
        with db() as con: con.execute('UPDATE users SET password=?',(old,))
        r=self.client.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h)
        self.assertEqual(r.status_code,200)
        with db() as con: self.assertTrue(con.execute('SELECT password FROM users').fetchone()[0].startswith('scrypt$131072$'))
        self.assertEqual(self.client.get('/api/domains').json()[0]['id'],d)

    def test_password_policy_and_duplicate_email(self):
        p={'name':'Ana','email':'ana@lab.test','password':'Corta-1234567'}
        self.assertEqual(self.client.post('/api/register',json=p,headers=self.h).status_code,422)
        p['password']='Una-clave-ficticia-123'
        a=self.client.post('/api/register',json=p,headers=self.h)
        b=self.client.post('/api/register',json=p,headers=self.h)
        self.assertEqual(a.status_code,201)
        self.assertEqual(b.status_code,409)
        with db() as con:self.assertEqual(con.execute('SELECT count(*) FROM users').fetchone()[0],1)

    def test_closed_registration_and_quotas(self):
        from unittest.mock import patch
        self.account();d=self.domain();i=self.incident(d)
        with patch('app.main.REGISTRATION_OPEN',False):
            self.assertFalse(self.client.get('/api/config').json()['registration_open'])
            self.assertEqual(self.client.post('/api/register',json={'name':'Bea','email':'bea@lab.test','password':'Otra-frase-larga-456'},headers=self.h).status_code,403)
        with patch.dict('app.main.LIMITS',domains=1,incidents=1,notes=1):
            self.assertEqual(self.client.post('/api/domains',json={'name':'otro.test'},headers=self.h).status_code,409)
            self.assertEqual(self.client.post('/api/incidents',json={'domain_id':d,'title':'Nuevo','description':'Otra incidencia','category':'otro','priority':'media'},headers=self.h).status_code,409)
            self.assertEqual(self.client.post(f'/api/incidents/{i}/notes',json={'body':'Primera'},headers=self.h).status_code,201)
            self.assertEqual(self.client.post(f'/api/incidents/{i}/notes',json={'body':'Segunda'},headers=self.h).status_code,409)
            self.assertEqual(self.client.post('/api/demo',json={'case_ids':[1,2,3,4,5,6]},headers=self.h).status_code,409)
        self.assertEqual(len(self.client.get('/api/incidents').json()),1)

    def test_secure_cookie_profile(self):
        from unittest.mock import patch
        self.account()
        with patch('app.main.SECURE',True),patch('app.main.COOKIE_NAME','__Host-vigia_session'):
            with TestClient(app,base_url='https://localhost') as c:
                r=c.post('/api/login',json={'email':'ana@lab.test','password':'Una-clave-ficticia-123'},headers=self.h)
                cookie=r.headers['set-cookie']
                for attribute in ['__Host-vigia_session=','HttpOnly','Secure','Path=/','SameSite=strict']:
                    self.assertIn(attribute,cookie)
                self.assertNotIn('Domain=',cookie)
                self.assertEqual(c.get('/api/me').status_code,200)
                self.assertIn('Strict-Transport-Security',r.headers)

    def test_error_response_does_not_leak(self):
        from unittest.mock import patch
        with patch('app.main.db',side_effect=RuntimeError('FAKE_SECRET_MUST_NOT_LEAK')):
            c=TestClient(app,raise_server_exceptions=False)
            r=c.get('/health')
            self.assertEqual(r.status_code,500)
            self.assertNotIn('FAKE_SECRET',r.text)
            self.assertIn('Content-Security-Policy',r.headers)
            c.close()

    def test_attribution_cannot_be_forged_and_updates(self):
        self.account(); d=self.domain(); i=self.incident(d)
        row=self.client.get(f'/api/incidents/{i}').json()
        self.assertEqual(row['created_by_name'],'Ana')
        self.assertEqual(row['creation_source'],'user')
        self.assertIsNone(row['updated_by'])
        self.assertEqual(self.client.patch(f'/api/incidents/{i}',json={'status':'resuelta','updated_by':999},headers=self.h).status_code,422)
        self.assertEqual(self.client.patch(f'/api/incidents/{i}',json={'status':'resuelta'},headers=self.h).status_code,200)
        row=self.client.get(f'/api/incidents/{i}').json()
        self.assertEqual(row['updated_by'],row['created_by'])
        self.assertIsNotNone(row['updated_at'])
        self.client.post(f'/api/incidents/{i}/notes',json={'body':'Una nota atribuida'},headers=self.h)
        row=self.client.get(f'/api/incidents/{i}').json()
        self.assertEqual(row['notes'][0]['author_id'],row['created_by'])
        self.assertEqual(row['notes'][0]['author_name'],'Ana')
        self.assertEqual(self.client.get('/api/incidents').json()[0]['updated_by_name'],'Ana')

    def test_demo_attribution_is_system(self):
        self.account()
        self.client.post('/api/demo',json={'case_ids':[1,2,3,4,5,6]},headers=self.h)
        row=self.client.get('/api/incidents').json()[0]
        self.assertEqual(row['creation_source'],'demo')
        self.assertIsNone(row['created_by'])
        note=self.client.get('/api/incidents/'+str(row['id'])).json()['notes'][0]
        self.assertEqual(note['source'],'demo')

    def test_attribution_migration_preserves_unknown_history(self):
        import sqlite3
        from app.main import migrate_attribution
        with sqlite3.connect(':memory:') as con:
            con.row_factory=sqlite3.Row
            con.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY); CREATE TABLE incidents(id INTEGER PRIMARY KEY,title TEXT); CREATE TABLE notes(id INTEGER PRIMARY KEY,body TEXT); INSERT INTO incidents VALUES(1,'Histórico'); INSERT INTO notes VALUES(1,'Nota antigua');")
            migrate_attribution(con)
            migrate_attribution(con)
            row=con.execute('SELECT * FROM incidents').fetchone()
            self.assertEqual(row['title'],'Histórico')
            self.assertEqual(row['creation_source'],'legacy')
            self.assertIsNone(row['created_by'])
            self.assertIsNone(row['updated_by'])
            self.assertIsNone(con.execute('SELECT author_id FROM notes').fetchone()[0])

    def test_unique_username_normalization(self):
        self.account()
        for name in ['ANA',' Ana ','Ａｎａ']:
            r=self.client.post('/api/register',json={'name':name,'email':'other@lab.test','password':'Una-clave-ficticia-123'},headers=self.h)
            self.assertEqual(r.status_code,409)
        with db() as con: self.assertEqual(con.execute('SELECT count(*) FROM users').fetchone()[0],1)

    def test_welcome_saved_per_account_and_restart(self):
        self.account()
        self.assertFalse(self.client.get('/api/me').json()['welcome_seen'])
        self.assertEqual(self.client.post('/api/welcome-seen',json={},headers={'X-Vigia-Request':'1'}).status_code,403)
        self.assertEqual(self.client.post('/api/welcome-seen',json={},headers=self.h).status_code,200)
        with TestClient(app) as second:
            second.cookies.update(self.client.cookies)
            self.assertTrue(second.get('/api/me').json()['welcome_seen'])
        self.account('bea@lab.test')
        self.assertFalse(self.client.get('/api/me').json()['welcome_seen'])

    def test_admin_bootstrap_persistent_and_private(self):
        from unittest.mock import patch
        from app.main import bootstrap_admin, verify_password
        with db() as con, tempfile.TemporaryDirectory() as tmp, patch('app.main.DATA',Path(tmp)):
            con.execute("DELETE FROM app_settings WHERE key='admin_initialized'")
            bootstrap_admin(con)
            row=con.execute("SELECT * FROM users WHERE name_key='admin'").fetchone()
            secretfile=Path(tmp)/'admin-inicial.txt'
            text=secretfile.read_text()
            password=text.split('Contraseña: ')[1].splitlines()[0]
            self.assertTrue(verify_password(password,row['password'])[0])
            self.assertEqual(secretfile.stat().st_mode&0o777,0o600)
            self.assertEqual(row['email'],'admin@vigia.test')
            self.assertEqual(row['role'],'admin')
            self.assertEqual(con.execute('SELECT count(*) FROM domains WHERE user_id=?',(row['id'],)).fetchone()[0],0)
            self.assertEqual(con.execute('SELECT count(*) FROM incidents WHERE user_id=?',(row['id'],)).fetchone()[0],0)
            bootstrap_admin(con)
            self.assertEqual(secretfile.read_text(),text)
            self.assertEqual(con.execute("SELECT count(*) FROM users WHERE name_key='admin'").fetchone()[0],1)

    def test_legacy_duplicate_names_preserve_data(self):
        import sqlite3
        from app.main import migrate_accounts
        with sqlite3.connect(':memory:') as con:
            con.row_factory=sqlite3.Row
            con.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT); INSERT INTO users VALUES(1,'Ana'),(2,'ANA');")
            migrate_accounts(con)
            names=[r['name'] for r in con.execute('SELECT name FROM users ORDER BY id')]
            self.assertEqual(names,['Ana','ANA #2'])
            migrate_accounts(con)
            self.assertEqual([r['name'] for r in con.execute('SELECT name FROM users ORDER BY id')],names)

    def test_admin_permissions_and_global_read(self):
        self.account(); own=self.incident(self.domain())
        for path in ['/api/admin/users','/api/admin/summary','/api/admin/incidents','/api/admin/incidents/'+str(own)]:
            self.assertEqual(self.client.get(path).status_code,403)
        self.assertEqual(self.client.patch('/api/admin/users/999',json={'active':False},headers=self.h).status_code,403)
        self.assertEqual(self.client.post('/api/admin/users/999/revoke',json={},headers=self.h).status_code,403)
        with db() as con: con.execute("UPDATE users SET role='admin' WHERE email='ana@lab.test'")
        cookies=dict(self.client.cookies); headers=dict(self.h)
        self.account('bea@lab.test'); other=self.incident(self.domain())
        self.client.cookies.clear();self.client.cookies.update(cookies);self.h=headers
        self.assertEqual(self.client.get('/api/me').json()['role'],'admin')
        summary=self.client.get('/api/admin/summary').json()
        self.assertEqual(summary['users'],2)
        self.assertEqual(summary['incidents'],2)
        self.assertEqual(len(self.client.get('/api/incidents').json()),1)
        self.assertEqual(self.client.get('/api/incidents/'+str(other)).status_code,404)
        result=self.client.get('/api/admin/incidents/'+str(other)).json()
        self.assertEqual(result['owner_name'],'bea')
        self.assertNotIn('password',self.client.get('/api/admin/users').text)
        self.assertEqual(len(self.client.get('/api/admin/incidents').json()['items']),2)
        self.assertEqual(self.client.get('/api/admin/incidents?offset=-1').status_code,422)
        self.assertEqual(self.client.get('/api/admin/incidents?offset=50').json()['items'],[])

    def test_admin_disable_reenable_and_revoke(self):
        self.account()
        with db() as con:
            con.execute("UPDATE users SET role='admin' WHERE email='ana@lab.test'")
            admin=con.execute("SELECT id FROM users WHERE email='ana@lab.test'").fetchone()[0]
        cookies=dict(self.client.cookies); headers=dict(self.h)
        self.account('bea@lab.test'); domain=self.domain()
        victim_cookies=dict(self.client.cookies)
        with db() as con: victim=con.execute("SELECT id FROM users WHERE email='bea@lab.test'").fetchone()[0]
        self.client.cookies.clear();self.client.cookies.update(cookies);self.h=headers
        path='/api/admin/users/'+str(victim)
        self.assertEqual(self.client.patch(path,json={'active':False},headers={'X-Vigia-Request':'1'}).status_code,403)
        self.assertEqual(self.client.patch('/api/admin/users/'+str(admin),json={'active':False},headers=self.h).status_code,409)
        self.assertEqual(self.client.patch(path,json={'active':False},headers=self.h).status_code,200)
        with TestClient(app) as second:
            second.cookies.update(victim_cookies)
            self.assertEqual(second.get('/api/me').status_code,401)
            payload={'email':'bea@lab.test','password':'Una-clave-ficticia-123'}
            self.assertEqual(second.post('/api/login',json=payload,headers={'X-Vigia-Request':'1'}).status_code,401)
            self.client.patch(path,json={'active':True},headers=self.h)
            self.assertEqual(second.post('/api/login',json=payload,headers={'X-Vigia-Request':'1'}).status_code,200)
            self.assertEqual(second.get('/api/domains').json()[0]['id'],domain)
            self.assertEqual(self.client.post(path+'/revoke',json={},headers=self.h).status_code,200)
            self.assertEqual(second.get('/api/me').status_code,401)

    def test_public_registration_cannot_set_admin_role(self):
        r=self.client.post('/api/register',json={'name':'Mallory','email':'m@lab.test','password':'Una-clave-ficticia-123','role':'admin'},headers=self.h)
        self.assertEqual(r.status_code,422)
        self.account()
        self.assertEqual(self.client.get('/api/me').json()['role'],'user')

    def test_migration_promotes_only_reserved_admin(self):
        import sqlite3
        from app.main import migrate_accounts
        with sqlite3.connect(':memory:') as con:
            con.row_factory=sqlite3.Row
            con.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT); INSERT INTO users VALUES(1,'admin'),(2,'Ana');")
            migrate_accounts(con)
            self.assertEqual([r['role'] for r in con.execute('SELECT role FROM users ORDER BY id')],['admin','user'])
            con.execute("UPDATE users SET role='user' WHERE id=1")
            migrate_accounts(con)
            self.assertEqual(con.execute('SELECT role FROM users WHERE id=1').fetchone()[0],'user')

    def test_demo_selection_removal_and_reload(self):
        self.account(); domain=self.domain(); own=self.incident(domain)
        r=self.client.post('/api/demo',json={'case_ids':[1,4]},headers=self.h)
        self.assertEqual(r.json()['added'],2)
        data=self.client.get('/api/demo').json()
        self.assertEqual(len(data['loaded']),2)
        self.assertEqual(sum(c['loaded'] for c in data['catalog']),2)
        ident=data['loaded'][0]['id']
        self.client.post(f'/api/incidents/{ident}/notes',json={'body':'Mi nota en un ejemplo'},headers=self.h)
        r=self.client.request('DELETE','/api/demo',json={'incident_ids':[ident]},headers=self.h)
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.client.get(f'/api/incidents/{own}').status_code,200)
        self.assertEqual(self.client.get(f'/api/incidents/{ident}').status_code,404)
        with db() as con:self.assertEqual(con.execute('SELECT count(*) FROM notes WHERE incident_id=?',(ident,)).fetchone()[0],0)
        self.assertEqual(len(self.client.get('/api/domains').json()),1)
        self.assertEqual(self.client.post('/api/demo',json={'case_ids':[1,4]},headers=self.h).json()['added'],1)
        self.assertEqual(len(self.client.get('/api/incidents').json()),3)

    def test_demo_deletion_protects_personal_and_foreign_cases(self):
        self.account(); own=self.incident(self.domain())
        self.client.post('/api/demo',json={'case_ids':[1]},headers=self.h)
        example=self.client.get('/api/demo').json()['loaded'][0]['id']
        # Even a manually renamed title must not authorize deletion.
        with db() as con:con.execute("UPDATE incidents SET title='[DEMO] Personal' WHERE id=?",(own,))
        r=self.client.request('DELETE','/api/demo',json={'incident_ids':[example,own]},headers=self.h)
        self.assertEqual(r.status_code,409)
        self.assertEqual(self.client.get(f'/api/incidents/{example}').status_code,200)
        self.assertEqual(self.client.request('DELETE','/api/demo',json={'incident_ids':[example]},headers={'X-Vigia-Request':'1'}).status_code,403)
        self.account('bea@lab.test')
        self.assertEqual(self.client.request('DELETE','/api/demo',json={'incident_ids':[example]},headers=self.h).status_code,404)
        self.assertEqual(self.client.get('/api/demo').json()['loaded'],[])

    def test_demo_selection_validation_and_exact_quotas(self):
        from unittest.mock import patch
        self.account();self.domain()
        for ids in [[],[0],[7],[1,1]]:
            self.assertEqual(self.client.post('/api/demo',json={'case_ids':ids},headers=self.h).status_code,422)
        with patch.dict('app.main.LIMITS',domains=1,incidents=1):
            self.assertEqual(self.client.post('/api/demo',json={'case_ids':[1]},headers=self.h).json()['added'],1)
            self.assertEqual(self.client.post('/api/demo',json={'case_ids':[1]},headers=self.h).json()['added'],0)
            self.assertEqual(self.client.post('/api/demo',json={'case_ids':[2]},headers=self.h).status_code,409)
        self.assertEqual(len(self.client.get('/api/domains').json()),1)

if __name__=='__main__': unittest.main()
