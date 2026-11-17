"""Lanzador local: clave persistente, loopback y HTTPS opcional con certificado confiable."""
import argparse
import os
from pathlib import Path
import secrets
import stat
import sys


def prepare_env(root):
    config=root/'.env'
    if not config.exists():
        with open(config,'x',opener=lambda path, flags: os.open(path,flags,0o600)) as f:
            f.write('SESSION_SECRET='+secrets.token_urlsafe(48)+'\nBIND_IP=127.0.0.1\nCOOKIE_SECURE=false\nALLOWED_HOSTS=localhost,127.0.0.1\nREGISTRATION_OPEN=true\n')
    if config.is_symlink(): raise SystemExit('.env no debe ser un enlace simbólico.')
    if config.stat().st_uid != os.getuid(): raise SystemExit('.env debe pertenecer a tu usuario.')
    config.chmod(stat.S_IRUSR|stat.S_IWUSR)
    values={}
    for line in config.read_text().splitlines():
        line=line.strip()
        if line and not line.startswith('#') and '=' in line:
            k,v=line.split('=',1)
            if k in ('SESSION_SECRET','COOKIE_SECURE','ALLOWED_HOSTS','REGISTRATION_OPEN'):
                values[k]=v.strip().strip('"').strip("'")
    if len(values.get('SESSION_SECRET','')) < 32:
        raise SystemExit('Falta una SESSION_SECRET de al menos 32 caracteres en .env.')
    return values


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dev',action='store_true',help='Recargar al editar, solo desarrollo')
    p.add_argument('--certfile',type=Path)
    p.add_argument('--keyfile',type=Path)
    p.add_argument('--port',type=int,default=8000)
    p.add_argument('--init-only',action='store_true',help='Preparar .env y terminar, sin imprimir secretos')
    args=p.parse_args()
    root=Path(__file__).resolve().parent
    os.chdir(root)
    values=prepare_env(root)
    if args.init_only:
        print('.env preparado con permisos 600. No publiques este archivo.')
        return
    if bool(args.certfile)!=bool(args.keyfile): p.error('Indica tanto certificado como clave.')
    if args.certfile:
        if not args.certfile.is_file() or not args.keyfile.is_file(): p.error('No se encuentran los archivos TLS.')
        values['COOKIE_SECURE']='true'
    elif values.get('COOKIE_SECURE','false').lower()=='true':
        p.error('COOKIE_SECURE=true requiere --certfile y --keyfile en este lanzador.')
    os.environ.update(values)
    command=[sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(args.port),
             '--no-proxy-headers','--no-server-header','--no-access-log','--limit-concurrency','32','--timeout-keep-alive','5']
    if args.dev: command.append('--reload')
    if args.certfile: command+=['--ssl-certfile',str(args.certfile.resolve()),'--ssl-keyfile',str(args.keyfile.resolve())]
    os.execv(sys.executable,command)

if __name__=='__main__': main()
