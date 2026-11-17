# Operación segura del laboratorio

## Acceso recomendado

Mantén BIND_IP=127.0.0.1. En el portátil:

```bash
ssh -N -L 8000:127.0.0.1:8000 TU_USUARIO@192.168.56.102
```

Abre http://localhost:8000. El tramo portátil→VM va cifrado por SSH; los tramos loopback permanecen locales. Verifica el usuario/IP antes de usar el ejemplo. No abras puertos del router. La red interna de Compose limita la salida del contenedor; la descarga de dependencias se realiza durante la construcción, no al arrancar la aplicación.

## HTTPS opcional

Se incluyen soporte TLS directo en el lanzador y compose.https.yaml. Debes disponer de `tls/server.crt` y `tls/server.key`, con SAN para localhost y 127.0.0.1 y una cadena de confianza que el navegador valide. No se entrega una clave privada ni se crea una CA confiable automáticamente. Usa un certificado de tu CA de laboratorio y confía en ella mediante el procedimiento del sistema/navegador. No ignores avisos ni uses curl -k como validación.

Portátil:

```bash
python iniciar.py --certfile tls/server.crt --keyfile tls/server.key
```

Abre https://localhost:8000. El lanzador activa cookies Secure. El prefijo __Host- impide cookies de dominio amplio. HSTS queda activo para el host; después el navegador puede forzar HTTPS en localhost, incluso al regresar a HTTP. Mantén ese perfil o elimina la política local únicamente cuando retires deliberadamente la prueba.

Docker:

```bash
docker compose -f compose.yaml -f compose.https.yaml up --build -d
```

Antes, la clave debe ser legible solo por el administrador y el UID del contenedor (10001), sin acceso de otros usuarios. Ejemplo desde el directorio del proyecto, cuando los archivos ya existan:

```bash
sudo chown -R 10001:10001 tls
sudo chmod 700 tls
sudo chmod 600 tls/server.key
sudo chmod 644 tls/server.crt
```

No utilices esos permisos para un servicio distinto sin revisar su usuario. El healthcheck valida la conexión TLS usando server.crt como raíz/archivo de confianza; si tu CA usa una cadena distinta, adapta el archivo de confianza y comprueba hostname. No se ha validado este perfil con un certificado real en esta entrega.

## Copia de seguridad local

Desde vigia, con el entorno virtual activo:

```bash
python tools/backup.py --output backups/vigia-antes-de-actualizar.db
```

Usa un nombre nuevo en cada copia: nunca sobrescribe. Usa la API de backup de SQLite, verifica integridad y retira sesiones/contadores en la copia. No modifica el origen. El archivo contiene usuarios, hashes y casos; conserva permisos 600 y no lo publiques.

En Docker (conserva también una copia fuera del volumen):

```bash
docker compose exec web python tools/backup.py --source /app/data/vigia.db --output /app/data/backups/vigia-antes-de-actualizar.db
mkdir -m 700 -p backups
docker compose cp web:/app/data/backups/vigia-antes-de-actualizar.db backups/vigia-antes-de-actualizar.db
chmod 600 backups/vigia-antes-de-actualizar.db
```

No acumules copias indefinidamente; define retención y custodia fuera del host. No se configura una tarea automática sin conocer dónde guardarás esas copias.

## Comprobar restauración

1. Detén la instancia de destino. Conserva su directorio actual sin borrarlo.
2. Crea otro directorio de prueba y copia el código, `.env` y la copia como `data/vigia.db`; permisos del archivo 600 y directorio 700 para la cuenta ejecutora.
3. Arranca solo esa copia, con puerto diferente si la original sigue funcionando: `python iniciar.py --port 8001`.
4. Inicia sesión, compara dominios/incidencias/notas y consulta /health. La copia no conserva sesiones activas: hay que autenticarse.
5. Documenta fecha, integridad, recuentos y resultado. No declares que hay recuperación comprobada hasta realizar esta prueba con tus datos.

La prueba automatizada verifica una copia mínima y su integridad; no sustituye una restauración operativa de tu VM.

## Comprobaciones de despliegue sin revelar secretos

```bash
docker compose ps
docker compose exec web id
docker compose exec web python -c "import os; print(os.access('/app',os.W_OK))"
curl -fsS http://127.0.0.1:8000/health
docker compose logs --tail=30 web
```

El proceso debe ser UID 10001; `/app` no debe ser escribible, pero `/app/data` y `/app/logs` sí. No compartas `docker inspect` completo ni `docker compose config` resuelto: pueden contener SESSION_SECRET.

Con el despliegue arrancado, verificar manualmente acceso desde el host, persistencia tras reinicio, límites de memoria/CPU, aislamiento de red y rotación. Estos controles están declarados, no comprobados en tu máquina.

## Wazuh

La aplicación escribe eventos JSON en logs/events.jsonl. El agente del host necesita leerlo. Ahora los archivos nuevos usan permisos privados; si tu logcollector no ejecuta como root, configura grupo o ACL de solo lectura para su identidad real. No uses chmod 777. Conserva las reglas anteriores y valida las nuevas antes de reiniciar el manager.

Consulta WAZUH.md. Los nuevos eventos incluyen password_changed, password_change_denied, sessions_revoked, rate_limited, origin_denied y internal_error. No confundir password_changed con recuperación automática de una cuenta comprometida: requiere conocer la contraseña actual.
