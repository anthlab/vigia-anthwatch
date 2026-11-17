"""Copia SQLite consistente, íntegra y sin sesiones; nunca sobrescribe un destino."""
import argparse
import os
from pathlib import Path
import sqlite3


def backup(source, destination):
    source=Path(source).resolve()
    destination=Path(destination).resolve()
    if not source.is_file(): raise ValueError('No existe la base de datos de origen.')
    if source==destination: raise ValueError('Origen y destino deben ser distintos.')
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(fd)
    try:
        with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as src:
            with sqlite3.connect(destination) as dst:
                src.backup(dst)
                dst.execute('DELETE FROM sessions')
                dst.execute('DELETE FROM limits')
                result=dst.execute('PRAGMA integrity_check').fetchone()[0]
                if result!='ok': raise ValueError('La comprobación de integridad ha fallado.')
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',default='data/vigia.db')
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    path=backup(args.source,args.output)
    print(f'Copia íntegra creada: {path.name}. Contiene datos y hashes de contraseñas; protégela.')
