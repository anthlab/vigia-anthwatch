"""Primitivas de seguridad. Sin credenciales predefinidas."""
import hashlib
import hmac
import re
import secrets
from threading import BoundedSemaphore
from fastapi import HTTPException

HASH_SLOT = BoundedSemaphore(1)
SCRYPT_N = 131072


def derive(password, salt, n):
    # Un solo hash simultáneo evita multiplicar los ~128 MiB por solicitud.
    if not HASH_SLOT.acquire(timeout=2):
        raise HTTPException(503, 'Servicio ocupado. Inténtalo de nuevo.', headers={'Retry-After':'3'})
    try:
        return hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt), n=n,
                              r=8, p=1, maxmem=256*1024*1024).hex()
    finally:
        HASH_SLOT.release()


def password_hash(password):
    salt = secrets.token_hex(16)
    return f'scrypt${SCRYPT_N}$8$1${salt}${derive(password,salt,SCRYPT_N)}'


def verify_password(password, saved):
    if re.fullmatch(r'[0-9a-f]{32}:[0-9a-f]{128}', saved):
        salt, expected = saved.split(':')
        actual = derive(password, salt, 16384)
        return hmac.compare_digest(actual, expected), True
    parts = saved.split('$')
    if len(parts)!=6 or parts[:4]!=['scrypt',str(SCRYPT_N),'8','1']:
        return False, False
    salt, expected = parts[4:]
    if not re.fullmatch(r'[0-9a-f]{32}',salt) or not re.fullmatch(r'[0-9a-f]{128}',expected):
        return False, False
    return hmac.compare_digest(derive(password,salt,SCRYPT_N),expected), False


def valid_new_password(value):
    # Se permiten espacios y Unicode. No se recorta ni se trunca la contraseña.
    if not 15 <= len(value) <= 128 or len(set(value)) < 5 or not value.strip():
        raise ValueError('Usa una frase de contraseña de 15 a 128 caracteres.')
    return value


def protect_response(response, secure=False):
    response.headers.update({
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY',
        'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
        'Referrer-Policy':'no-referrer', 'Cache-Control':'no-store',
        'Cross-Origin-Resource-Policy':'same-origin', 'Cross-Origin-Opener-Policy':'same-origin',
    })
    if secure: response.headers['Strict-Transport-Security']='max-age=31536000'
    return response
