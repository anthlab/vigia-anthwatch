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
        r=self.client.post('/api/register',json={'name':'Ana','email':email,'password':'Una-clave-ficticia-123'},headers=self.h)
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
        r=self.client.post('/api/demo',json={},headers=self.h)
        self.assertEqual(r.json()['added'],6)
        self.assertEqual(len(self.client.get('/api/domains').json()),3)
        cases=self.client.get('/api/incidents').json()
        self.assertEqual(len(cases),6)
        self.assertEqual({c['status'] for c in cases},{'pendiente','investigacion','resuelta'})
        self.assertTrue(all(c['title'].startswith('[DEMO]') for c in cases))
        self.assertEqual(self.client.post('/api/demo',json={},headers=self.h).json()['added'],0)
        self.assertEqual(len(self.client.get('/api/incidents').json()),6)
        self.client.cookies.clear()
        self.account('otra@lab.test')
        self.assertEqual(self.client.get('/api/incidents/'+str(cases[0]['id'])).status_code,404)

    def test_registration_has_demo(self):
        r=self.client.post('/api/register',json={'name':'Demo','email':'demo@lab.test','password':'Clave-ficticia-123'},headers=self.h)
        self.assertEqual(r.status_code,201)
        with db() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM incidents').fetchone()[0],6)
            self.assertEqual(con.execute('SELECT count(*) FROM domains').fetchone()[0],3)

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

    def test_password_policy_and_registration_privacy(self):
        p={'name':'Ana','email':'ana@lab.test','password':'Corta-1234567'}
        self.assertEqual(self.client.post('/api/register',json=p,headers=self.h).status_code,422)
        p['password']='Una-clave-ficticia-123'
        a=self.client.post('/api/register',json=p,headers=self.h)
        b=self.client.post('/api/register',json=p,headers=self.h)
        self.assertEqual(a.status_code,b.status_code)
        self.assertEqual(a.json(),b.json())
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
            self.assertEqual(self.client.post('/api/demo',json={},headers=self.h).status_code,409)
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

if __name__=='__main__': unittest.main()
