# Informe de seguridad · Vigía v3

Fecha: 17 de noviembre de 2026. Ámbito: código de Vigía, lanzador, configuración propuesta de Docker y pruebas automatizadas. Autoría: implementación y revisión asistida; no constituye auditoría independiente ni certificación.

## 1. Resultado y límites de la revisión

Se ha endurecido la aplicación para su uso en un laboratorio privado, manteniendo los seis casos ficticios editables. Pasan 23 pruebas automatizadas en un entorno Python 3.12 limpio. pip-audit 2.10.1 no ha encontrado vulnerabilidades conocidas en las 13 dependencias de ejecución fijadas en requirements.lock en la fecha indicada. Bandit 1.9.4 deja tres avisos bajos revisados; no se han ocultado.

Estos resultados no demuestran ausencia de vulnerabilidades. No se ha desplegado en el portátil del alumno ni en anthwatch-server, no se ha ejecutado Docker aquí y no se ha verificado la ingesta de Wazuh. Tampoco se ha completado una prueba visual de todos los controles nuevos en navegador. Las evidencias técnicas generadas están en docs/evidencias.

## 2. Qué protegemos y frente a quién

Activos: contraseñas, sesiones, dominios e incidencias privados, notas, registros y disponibilidad del laboratorio. Se consideran usuarios anónimos que envían entradas incorrectas, usuarios autenticados que intentan acceder a otra cuenta y páginas externas que intentan inducir peticiones. El administrador del host, Docker y los archivos SQLite es de confianza: la aplicación no puede impedir que ese administrador lea o modifique sus archivos.

Exposición prevista: localhost:8000; acceso remoto desde el portátil a la VM mediante túnel SSH. El perfil HTTPS es opcional y requiere certificados verificados. No se transforma el laboratorio en un servicio público de Internet.

## 3. Cambios realizados y justificación

| Área | Estado anterior | Implementación v3 | Comprobación |
|---|---|---|---|
| Lanzador | Uso de Path.open(opener=...) que impedía crear .env | Uso correcto de open; permisos 600, clave persistente, rechazo de enlace simbólico y propietario ajeno | test_launcher_creates_persistent_private_env |
| Contraseñas | scrypt N=16384, r=8, p=1 | scrypt N=131072, r=8, p=1; sal aleatoria; algoritmo y parámetros guardados con el hash | test_passwords_cookies_and_headers |
| Migración | Sin actualización de hashes | Verificación del formato antiguo y rehash al iniciar sesión correctamente, sin borrar la cuenta | test_legacy_hash_upgrades_without_data_loss |
| Recursos del hash | Hashes simultáneos sin cota | Un hash simultáneo por proceso; espera máxima de 2 s, después 503 | Revisión de security.py; límite no probado bajo carga concurrente |
| Política de contraseña | Mínimo 12 | Alta y cambio: 15–128 caracteres, sin truncar ni eliminar espacios; al menos cinco caracteres distintos | test_password_policy_and_registration_privacy |
| Registro | Respuesta diferente para correo existente | Mismo estado 201 y mensaje genérico para altas nuevas y duplicadas; se calcula hash en ambos casos | test_password_policy_and_registration_privacy |
| Sesiones | Varias sesiones podían coexistir | Una sesión activa por cuenta; un nuevo login revoca la anterior; vencimiento absoluto 1 h e inactividad 15 min | test_new_login_and_logout_all_revoke; test_idle_and_absolute_expiry |
| Credenciales | No había cambio de contraseña en la web | Panel Seguridad de la cuenta: exige contraseña actual y CSRF; cambia hash y revoca sesiones | test_password_change_revokes_and_checks_current |
| Cookies | HttpOnly, SameSite Strict, Secure opcional | Se mantiene; en HTTPS se usa __Host-vigia_session, Secure, Path=/ y sin Domain | test_secure_cookie_profile |
| Permisos | Control por propietario | Se mantiene en lectura, escritura, notas y carga demo; se eliminó SQL construido con el nombre de tabla | test_cross_user_isolation; test_demo_idempotent_and_owned |
| Entrada | Tamaño máximo, validadores | Tipos estrictos; atributos extra prohibidos; máximo 16 KiB también en fragmentos; 5 s para recibir el cuerpo | test_host_origin_and_body_size; test_stream_body_limit_and_timeout |
| Peticiones externas | JSON, cabecera propia, origen y CSRF | Se conservan; no CORS; hosts por defecto solo localhost y 127.0.0.1 | test_csrf_and_unauthenticated; test_host_origin_and_body_size |
| Abuso | Límite de login/registro | Límite general API, límite de cambio de contraseña, cotas de contadores y de registros | test_rate_limit_persists_and_expires; test_closed_registration_and_quotas |
| Errores | Respuesta genérica | Se garantiza CSP también en error interno; no se registran los nombres arbitrarios de campos inválidos | test_error_response_does_not_leak; test_logs_have_no_secrets |
| Cabeceras | CSP y cabeceras básicas | Añadidos COOP/CORP same-origin; HSTS solo con perfil seguro | Tests de cabeceras y revisión |
| Registros | Eventos estructurados rotados | ID de petición, nuevos eventos de seguridad y sin access log de Uvicorn para no guardar URL/query accidentalmente | test_logs_have_no_secrets |
| Docker | No root y raíz de solo lectura | Se mantiene; 512 MiB, 1 CPU, 100 PIDs, 32 conexiones concurrentes de Uvicorn, red interna y logs rotados | Configuración entregada, pendiente de prueba Docker |
| Copias | No había herramienta | Copia consistente vía SQLite backup API, integrity_check, destino exclusivo 600 y eliminación de sesiones/contadores de la copia | test_backup_integrity_no_sessions_no_overwrite |
| Dependencias | Solo tres versiones directas fijadas | 13 versiones directas y transitivas fijadas y auditadas | docs/evidencias/dependencias.json |

El coste nuevo de scrypt coincide con la configuración mínima N=2^17, r=8, p=1 recogida por OWASP. Las frases de al menos 15 caracteres se ajustan a su orientación cuando no existe MFA. Las cuentas anteriores con contraseñas de 12–14 caracteres siguen pudiendo entrar para no bloquear al usuario; conviene cambiarlas desde Seguridad de la cuenta. Migrar el hash no mejora una contraseña débil por sí solo.

## 4. Límites exactos implementados

| Control | Límite |
|---|---|
| Peticiones /api por IP | 120 por 60 segundos |
| Login por IP | 30 por 5 minutos |
| Login por cuenta | 8 por 5 minutos |
| Registro por IP | 5 por 5 minutos |
| Cambio de contraseña | 10 por IP y 8 por cuenta cada 5 minutos |
| Usuarios del laboratorio | 50 en total |
| Dominios | 50 por usuario |
| Incidencias | 200 por usuario |
| Notas | 100 por incidencia |
| Contadores activos del limitador | Máximo operativo de 10.000; ante saturación se rechaza con 503 |

Se cuentan intentos válidos e inválidos que alcanzan el limitador específico; el límite general se aplica antes de validar el modelo. Los contadores persisten en SQLite y se actualizan en una transacción. Las cuotas se comprueban en la transacción de inserción. Los ejemplos demo también respetan las cuotas; al cargarlos en una cuenta antigua se reserva conservadoramente espacio para tres dominios y seis casos.

Los límites no equivalen a protección completa frente a denegación de servicio. Un túnel SSH o una NAT pueden hacer que varios clientes compartan una IP y cuota. El bloqueo por cuenta puede ser inducido por otra persona; dura una ventana limitada, no es un bloqueo permanente. Reiniciar no elimina el contador, pero rotar SESSION_SECRET cambia las claves HMAC del limitador y revoca la validación de sesiones.

## 5. Auditoría estática y dependencias

Herramientas: Bandit 1.9.4; pip-audit 2.10.1. Se revisaron app/, iniciar.py y tools/, no solo los cambios.

Bandit encontró inicialmente una consulta SQL construida con una variable de tabla (B608). La tabla provenía de constantes del código, no del usuario, pero se sustituyó por un mapa de consultas literales para eliminar esa construcción y facilitar la revisión. En el análisis final quedan:

| Aviso | Ubicación | Clasificación tras revisar | Motivo |
|---|---|---|---|
| B606, bajo | iniciar.py, os.execv | Operación prevista, no inyección de shell | Se ejecuta sys.executable con una lista de argumentos; no hay shell ni texto de formulario en el comando. Requiere control del entorno local de confianza. |
| B105, bajo | main.py, límite 'password':10 | Falso positivo | Es un contador de intentos, no una contraseña. |
| B105, bajo | main.py, 'min_password':15 | Falso positivo | Es una longitud mínima, no una credencial. |

No se añadieron exclusiones para esconder esos resultados. Consulta el JSON para los números de línea de esta versión.

pip-audit examinó las 13 versiones fijadas con --disable-pip --no-deps: se usa ese modo porque requirements.lock enumera todas las dependencias de ejecución resueltas en un entorno limpio. No analiza el intérprete Python, el sistema operativo, la imagen Debian ni vulnerabilidades aún no publicadas. El archivo fija versiones pero no hashes de artefactos; no es un lock firmado ni garantiza integridad de la cadena de suministro. Volver a resolver versiones requiere repetir pruebas y auditoría, no actualizar a ciegas.

## 6. Evidencias disponibles

- evidencias/pruebas.txt: ejecución real de 23 pruebas; resultado OK.
- evidencias/dependencias.json: salida real de pip-audit, cero vulnerabilidades conocidas en las versiones consultadas.
- evidencias/bandit.json: salida real del análisis estático y avisos pendientes de contexto.
- requirements.lock: versiones usadas en las pruebas limpias.

Los casos [DEMO] de la aplicación NO son evidencias de auditoría, accesos reales ni incidentes detectados. No utilizarlos como resultados de la práctica.

## 7. Lo que debe validarse en tu entorno

1. Actualizar siguiendo ACTUALIZAR.md y conservar una copia anterior.
2. Abrir la web, entrar con tu cuenta y confirmar datos y casos.
3. Cambiar contraseña; verificar que la contraseña anterior y la sesión antigua dejan de funcionar.
4. Crear dos cuentas y repetir lectura/escritura de IDs ajenos en el alcance local autorizado.
5. Ejecutar las pruebas con requirements-dev.txt.
6. Construir Docker, comprobar usuario/puertos/red/read_only/límites, health y persistencia tras reinicio.
7. Verificar que la red interna admite el acceso previsto desde el host pero impide conexiones externas; no asumirlo solo por el YAML.
8. Si activas HTTPS, comprobar certificado, hostname, confianza del cliente y cookies; nunca desactivar validación para que una prueba pase.
9. Enviar eventos a Wazuh, validar primero reglas con analysisd -t y logtest y confirmar ingesta real.
10. Probar restauración de una copia en un directorio independiente antes de confiar en ella.

## 8. Riesgos residuales y mejoras siguientes

- No hay MFA, WebAuthn, verificación de correo ni recuperación por correo. Un usuario que conozca la contraseña puede autenticarse.
- La política no consulta contraseñas filtradas; la restricción de diversidad no sustituye una lista de contraseñas comprometidas.
- Existe compatibilidad transitoria con hashes anteriores. Su coste y tiempo de respuesta difieren hasta el siguiente acceso correcto. No se garantiza tiempo idéntico en todos los escenarios.
- TLS es opcional y no se activa automáticamente: el modo HTTP local se protege por aislamiento/túnel. No usar acceso directo por HTTP en una red no confiable.
- Los datos y las copias no están cifrados por la aplicación. Para protección ante pérdida del disco, usar cifrado del sistema/volumen y custodia de copias. El host de confianza puede leer hashes y notas.
- Los logs locales pueden alterarse desde el host y el reloj debe estar sincronizado. Wazuh aporta recolección externa, pero todavía no está conectado ni probado por esta entrega.
- No se han probado concurrencia intensa, consumo sostenido, carga, accesibilidad completa, todos los navegadores, Docker real ni TLS real. Las peticiones ya autenticadas y en curso pueden finalizar al mismo tiempo que una revocación; las siguientes se rechazan.
- Las cuotas limitan el crecimiento lógico, no sustituyen una cuota de disco ni supervisión de espacio. Las copias necesitan rotación externa.
- No hay garantía de producción ni cumplimiento íntegro de ASVS; para exposición pública hacen falta una revisión independiente y completar los controles pendientes.

## 9. Fuentes primarias

- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Docker Compose services: https://docs.docker.com/reference/compose-file/services/
- Docker Compose networks: https://docs.docker.com/reference/compose-file/networks/

Estas referencias orientan decisiones concretas; ninguna de estas organizaciones ha auditado o certificado Vigía.

## 10. Repetir las comprobaciones

Desde la carpeta del proyecto, usa un entorno separado para las herramientas de auditoría:

```bash
python3 -m venv .venv-audit
.venv-audit/bin/python -m pip install -r requirements-audit.txt
.venv-audit/bin/python -m bandit -r app iniciar.py tools
.venv-audit/bin/python -m pip_audit -r requirements.lock --disable-pip --no-deps
```

Bandit devuelve un código de salida distinto de cero por los avisos revisados: no equivale automáticamente a vulnerabilidad confirmada. pip-audit consulta un servicio externo con nombres/versiones de dependencias, no con tu base de datos. Mantén ese análisis en el entorno de desarrollo: la red interna del contenedor no está pensada para descargar o auditar dependencias en ejecución.

Para repetir los tests funcionales, utiliza el entorno de ejecución con requirements-dev.txt. El uso de herramientas automáticas sobre código/dependencias no es fuerza bruta contra el servicio. Las pruebas manuales de la práctica siguen limitadas a tu instancia autorizada.
