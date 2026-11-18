# Actualizar a Vigía v8 sin perder tu cuenta

## En tu portátil

1. Detén la versión anterior con Ctrl+C y comprueba que no quede otro proceso escribiendo la base.
2. Conserva la carpeta anterior. Descomprime el nuevo ZIP en otra carpeta (por ejemplo Vigia_v8).
3. Copia `data/` y `.env` de la versión anterior dentro de la nueva carpeta `vigia`. No copies la carpeta .venv. Los archivos son privados: no los subas a GitHub ni los entregues.
4. Si no tenías `.env`, el nuevo lanzador lo creará con una clave aleatoria. Tu cuenta y datos seguirán existiendo, pero tendrás que iniciar sesión.
5. Desde la NUEVA carpeta vigia:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python iniciar.py
```

Abre http://localhost:8000 y entra con tu cuenta. No hace falta registrarte si copiaste `data/`. El formato anterior de contraseñas se migra al iniciar sesión, sin borrar los datos. En Seguridad de la cuenta puedes establecer una frase nueva de al menos 15 caracteres. El cambio cierra todas las sesiones.

Si prefieres empezar de cero, omite copiar data/ y crea una cuenta nueva; empezará vacía. Cualquier cuenta puede seleccionar qué ejemplos cargar y cuáles retirar.

## Configuración después de comprobar el acceso

En `.env`, puedes cerrar el registro cuando hayas creado tus cuentas:

```dotenv
REGISTRATION_OPEN=false
ALLOWED_HOSTS=localhost,127.0.0.1
```

Reinicia la aplicación para aplicar cambios. No muestres SESSION_SECRET en capturas. Usa una clave generada aleatoriamente; el lanzador la conserva entre arranques.

El lanzador v4 no activa recarga automática por defecto. Para editar código localmente: `python iniciar.py --dev`. No uses ese modo para el despliegue del servidor.

## En Docker: mantener el mismo proyecto y volumen

No cambies el nombre del proyecto Compose sin identificar antes el volumen de datos, ya que podría crear un volumen vacío. No uses `down -v`. Conserva copia del código anterior y realiza primero la copia de seguridad descrita en docs/OPERACION_SEGURA.md.

Actualiza el código dentro del mismo directorio de proyecto, conservando `.env`, `logs/` y el volumen de Docker. Después:

```bash
docker compose up --build -d
docker compose ps
curl -fsS http://127.0.0.1:8000/health
```

El contenedor usa ahora 512 MiB, 1 CPU y una red interna. Debe validarse en tu Docker. No se ha ejecutado en tus VMs desde aquí. El agente Wazuh sigue funcionando en el host; no necesita conexión desde el contenedor porque lee el archivo montado de logs.

## Si hay que volver atrás

Conserva el directorio anterior y su copia de base de datos. Detén v4 antes de volver a ejecutar una versión anterior. Restaura la copia previa en un directorio separado: no uses la base ya actualizada con el código antiguo, porque los hashes nuevos no son compatibles con aquel verificador.

## Migración de autoría v4

Al arrancar, se añaden columnas a SQLite sin eliminar registros. Las incidencias y notas anteriores muestran autor no registrado: la versión previa no guardaba ese dato. El próximo cambio de estado o nota registrará al editor autenticado. Los nuevos ejemplos se atribuyen a Sistema · ejemplo. Haz una copia de seguridad antes de actualizar. Tras reiniciar, recarga el navegador con Ctrl+Mayús+R.

Consulta docs/CAMBIOS_V5.md para la cuenta admin, la contraseña inicial privada, los nombres únicos y la bienvenida.

Antes de actualizar, haz copia de data y conserva .env. Los nombres antiguos repetidos reciben un sufijo #ID; no se borran cuentas. El primer arranque crea admin si no existe y guarda su clave en data/admin-inicial.txt. Entra con admin@vigia.test y cambia la contraseña.

En v6 admin tiene permisos globales: consulta docs/ADMINISTRACION.md. Los usuarios normales mantienen su panel personal y no pueden usar las rutas administrativas.

En v7 admin inicia directamente en Administración; los usuarios normales, en Mi panel. Los datos existentes se conservan. Consulta docs/CAMBIOS_V7.md.

En v8 puedes elegir y eliminar ejemplos desde el mismo diálogo. La eliminación incluye sus notas, conserva dominios y casos personales, y permite recargar los ejemplos originales. Consulta docs/CAMBIOS_V8.md.
