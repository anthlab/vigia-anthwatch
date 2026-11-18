# Vigía v8 · Laboratorio de seguridad

Web en español para registrar dominios ficticios e investigar incidencias. Python/FastAPI, SQLite y Docker. Seis casos de ejemplo opcionales por cuenta, con notas y estados editables. No escanea ni consulta dominios externos.

## Empieza aquí

- **Ya usabas Vigía:** lee `ACTUALIZAR.md` para conservar tu cuenta, `.env` y datos.
- **Primera instalación en el portátil:** lee `EMPEZAR.md`.
- **Qué se ha protegido y cómo se ha probado:** `docs/SEGURIDAD.md`.
- **Copias, TLS y comprobaciones:** `docs/OPERACION_SEGURA.md`.
- **Práctica del PDF:** `docs/PRACTICA.md` y `entregas/PLANTILLA.md`.
- **Wazuh:** `docs/WAZUH.md`.

## Arranque en el portátil

Desde esta carpeta:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python iniciar.py
```

Abre http://localhost:8000. El lanzador crea `.env` privado si no existe y conserva la clave. Si ya existe pero está vacío o no contiene una clave válida, se detiene sin sobrescribirlo. No necesitas XAMPP ni MySQL. Para edición con recarga: `python iniciar.py --dev`.

## Funciones

Registro configurable, login, cierre de sesión, cambio de contraseña y revocación. Dominios .test, incidencias con prioridad/categoría/estado, notas y filtro. Aislamiento por propietario. Las cuentas nuevas empiezan sin dominios ni casos. Cargar casos de ejemplo permite elegir casos, evita duplicados y permite retirar los ejemplos propios con confirmación. Se crea una cuenta admin con contraseña aleatoria local; no se distribuyen contraseñas ni secretos en el ZIP.

Nueva contraseña: frase de 15–128 caracteres. Sesión: 15 minutos de inactividad, una hora máxima y una sesión por cuenta. Una nueva sesión revoca la anterior. La actualización admite las contraseñas antiguas para evitar bloquearte y renueva su hash al entrar.

## Despliegue previsto

| Equipo | Función |
|---|---|
| Portátil | Editar y acceder por navegador/túnel SSH |
| anthwatch-server | Docker, datos y agente Wazuh |
| anthwatch-client | Pruebas manuales dentro del alcance autorizado |
| anthwatch-wazuh | Recibir y analizar registros |

## Docker en anthwatch-server

Comprueba `docker --version` y `docker compose version`. Copia este proyecto (incluidos archivos ocultos) a una carpeta nueva, por ejemplo `/opt/vigia`. Desde ella, prepara .env sin imprimir la clave:

```bash
python3 iniciar.py --init-only
sudo install -d -o 10001 -g 10001 -m 0750 logs
docker compose up --build -d
docker compose ps
curl -fsS http://127.0.0.1:8000/health
docker compose logs --tail=30 web
```

`--init-only` solo usa la biblioteca estándar y no necesita instalar FastAPI en el host. El contenedor no root escribe SQLite en el volumen `vigia_data` y los eventos en el bind `logs/`. El servicio está limitado por defecto a loopback. No cambies BIND_IP a una IP pública ni abras puertos del router.

Para verlo desde tu portátil:

```bash
ssh -N -L 8000:127.0.0.1:8000 TU_USUARIO@192.168.56.102
```

Sustituye usuario/IP por los reales. Abre http://localhost:8000 en el portátil y conserva el túnel abierto. La IP registrada puede corresponder al túnel/puente, no al navegador original.

Para parar: `docker compose down`. Para reiniciar y comprobar persistencia: `docker compose restart web`. **No uses down -v:** borra el volumen. Para actualizar, conserva el mismo proyecto Compose y su volumen; sigue ACTUALIZAR.md.

HTTPS opcional: compose.https.yaml y el lanzador admiten certificados; consulta OPERACION_SEGURA.md. No se proporcionan claves privadas ni se presupone confianza automática del navegador.

## Pruebas

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

Pruebas en directorios temporales, sin usar tus cuentas ni tu base. La entrega pasa 37 pruebas. pip-audit no encontró vulnerabilidades conocidas en las 13 dependencias fijadas al revisarlas. Ver evidencia y límites en docs/VERIFICACION.md. Las versiones están fijadas pero el lock no contiene hashes de distribución.

## Seguridad y limitaciones

Para laboratorio privado: hash scrypt reforzado, CSRF, permisos, CSP, cuotas, límites de intentos, sesiones revocables, logs rotados y contenedor restringido. No es una garantía de seguridad absoluta ni un servicio listo para Internet. No tiene MFA ni recuperación de contraseña por correo; datos/copias no cifrados por la aplicación. Docker/TLS/Wazuh y la restauración con tus datos quedan pendientes de validar en tus máquinas.

No subas a GitHub ni entregues `.env`, `data/`, `logs/`, `backups/`, bases de datos o claves TLS. Los ejemplos demo no son evidencias reales.

Consulta docs/CAMBIOS_V5.md para la cuenta admin, la contraseña inicial privada, los nombres únicos y la bienvenida.

En v6 admin tiene permisos globales: consulta docs/ADMINISTRACION.md. Los usuarios normales mantienen su panel personal y no pueden usar las rutas administrativas.

En v7 admin inicia directamente en Administración; los usuarios normales, en Mi panel. Los datos existentes se conservan. Consulta docs/CAMBIOS_V7.md.

En v8 puedes elegir y eliminar ejemplos desde el mismo diálogo. La eliminación incluye sus notas, conserva dominios y casos personales, y permite recargar los ejemplos originales. Consulta docs/CAMBIOS_V8.md.
