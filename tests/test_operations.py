import asyncio
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from iniciar import prepare_env
from tools.backup import backup
from app.main import BodyLimit

class OperationsTests(unittest.TestCase):
    def test_launcher_creates_persistent_private_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            first=prepare_env(root)
            second=prepare_env(root)
            self.assertEqual(first['SESSION_SECRET'],second['SESSION_SECRET'])
            self.assertGreaterEqual(len(first['SESSION_SECRET']),48)
            self.assertEqual((root/'.env').stat().st_mode&0o777,0o600)

    def test_backup_integrity_no_sessions_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'source.db';dst=root/'copy.db'
            with sqlite3.connect(src) as c:
                c.executescript("CREATE TABLE sessions(token TEXT); CREATE TABLE limits(key TEXT); CREATE TABLE users(name TEXT); INSERT INTO sessions VALUES('fake'); INSERT INTO users VALUES('Ficticio');")
            backup(src,dst)
            with sqlite3.connect(dst) as c:
                self.assertEqual(c.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(c.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
                self.assertEqual(c.execute('SELECT name FROM users').fetchone()[0],'Ficticio')
            self.assertEqual(dst.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):backup(src,dst)
            with sqlite3.connect(src) as c:self.assertEqual(c.execute('SELECT count(*) FROM sessions').fetchone()[0],1)

    def test_stream_body_limit_and_timeout(self):
        async def check(slow=False):
            messages=[];calls=[]
            async def downstream(scope,receive,send):calls.append(True)
            async def send(message):messages.append(message)
            chunks=iter([b'x'*9000,b'x'*9000])
            async def receive():
                if slow: await asyncio.sleep(.1)
                return {'type':'http.request','body':next(chunks),'more_body':True}
            await BodyLimit(downstream,timeout=.01)({'type':'http','method':'POST'},receive,send)
            self.assertFalse(calls)
            self.assertEqual(messages[0]['status'],408 if slow else 413)
        asyncio.run(check())
        asyncio.run(check(True))

if __name__=='__main__':unittest.main()
