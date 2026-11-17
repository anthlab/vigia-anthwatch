# Práctica con Vigía

Adaptación propia del ejemplo CiberFaro. El objetivo es observar y documentar; no afirmar que una aplicación es invulnerable. Por defecto se mantiene el puerto en 127.0.0.1 y se accede por túnel SSH. Cualquier ampliación a la red host-only debe figurar en el alcance autorizado.

## Sesión 1 · Despliegue y observabilidad

Explica Dockerfile (imagen y proceso), compose.yaml (servicio, puertos y volúmenes), `.env.example` (nombres de variables, nunca secretos), bind local y persistencia. Sigue README. Guarda salidas de `docker compose ps`, `/health` y logs sin secretos. Crea un dominio y una incidencia, reinicia el contenedor y comprueba sus IDs/contenido. Repite tras down/up sin -v.

## Sesión 2 · Configuración

Cinco decisiones implementadas que debes revisar y probar:

| Decisión | Motivo | Evidencia posible |
|---|---|---|
| Puerto limitado a loopback | Reducir exposición | compose y escucha de red |
| Proceso no root, capacidades eliminadas, raíz de solo lectura | Limitar modificaciones del contenedor | Dockerfile e inspect sin volcar variables |
| Hash scrypt con sal y sesiones revocables | No almacenar contraseñas en claro | Código y pruebas |
| Permisos por propietario y SQL parametrizado | Evitar accesos ajenos e inyección SQL | Prueba con cuentas A/B |
| Token CSRF, CSP, texto en DOM y cookies HttpOnly | Reducir peticiones cruzadas y ejecución de contenido | Cabeceras y pruebas |

Tres limitaciones mínimas: HTTP local sin TLS, ausencia de MFA y recuperación de cuentas, ausencia de copias automáticas y auditoría resistente a manipulación. Un usuario con control del host puede modificar los logs locales. Recogerlos fuera mediante Wazuh mejora la separación, sin garantizar integridad absoluta.

Mejoras priorizadas: P1 verificar los límites de intentos y definir cuotas de almacenamiento; P1 definir copia/restauración; P2 HTTPS si se amplía el alcance; P2 automatizar prueba de expiración de sesiones; P3 incorporar métricas. Mantener el entorno privado.

En el repositorio:

```bash
git check-ignore -v .env
git ls-files .env
```

La primera orden debe identificar `.gitignore`; la segunda no debe listar `.env`. No ejecutes `git add -f .env`.

## Sesión 3 · Revisión manual

Alcance: únicamente tu instancia de Vigía, cuentas ficticias y horarios acordados. No fuerza bruta, escaneos externos ni automatización agresiva. No hace falta introducir fallos deliberados.

| ID | Acción manual | Resultado esperado |
|---|---|---|
| HE-01 | Dejar obligatorio vacío | Navegador impide enviar; documentar que esto solo prueba el cliente |
| HE-02 | Cambiar con herramientas del navegador una petición JSON para enviar dominio vacío | Servidor devuelve 422 |
| HE-03 | Probar `https://empresa.test`, `empresa.com`, `-empresa.test` | Rechazo 422 del servidor |
| HE-04 | Enviar un título de más de 120 caracteres modificando una sola petición | Rechazo 422 |
| HE-05 | Registrar dos veces un dominio nuevo, por ejemplo `duplicado.test`, en la misma cuenta | 409 sin error interno |
| HE-06 | Poner `<b>prueba</b>` en descripción/nota | Se presenta literalmente, no como HTML |
| HE-07 | Copiar un ID propio de A y consultarlo con B | 404; lista de B vacía |
| HE-08 | Intentar actualizar estado/añadir nota al ID de A con B | 404 y evento access_denied |
| HE-09 | Quitar X-CSRF-Token de una petición de escritura | 403 |
| HE-10 | Cerrar sesión y volver a solicitar datos privados | 401, aunque se reutilice una cookie antigua |
| HE-11 | Una contraseña incorrecta manual | 401 genérico; evento login_failed |

Usa la pestaña Red del navegador para inspeccionar o editar/repetir UNA petición cada vez. Si el navegador bloquea el formulario, no concluyas que el servidor lo ha validado. Guarda código HTTP y respuesta. Una entrada inválida no demuestra un ataque ni una vulnerabilidad.

Para cada observación: pasos, precondiciones, esperado, real, evidencia, clasificación (confirmada/indicio/falso positivo cuando corresponda), mitigación y límites. Un control que funciona se registra como prueba satisfactoria, no se inventa un hallazgo.

## Sesión 4 · Incidente simulado

Escenario ficticio: una persona obtiene la contraseña de una cuenta de laboratorio. Con esa cuenta se realiza UNA sesión autorizada y una modificación de una incidencia. Documenta explícitamente que eres tú representando al intruso y no un ataque real.

1. Anota tiempos UTC reales de la simulación y acciones realizadas.
2. Recoge login_ok, incident_updated y logout; si Wazuh está integrado, IDs de alertas.
3. Separa hechos observados de supuestos (no se puede probar quién estaba ante el teclado).
4. Propón contención: aislar servicio, revocar sesiones desde mantenimiento y restablecer contraseña. La UI permite cambiar la contraseña con la actual y cerrar sesiones; no hay recuperación por correo ni consola administrativa. Si no se conoce la contraseña, hace falta un procedimiento de mantenimiento autorizado.
5. Recuperación: restaurar datos de una copia verificada, corregir causa y comprobar accesos.
6. Lecciones: MFA, límites de acceso, retención de evidencias y copias. Nunca usar datos de empresas.

## Reto opcional

La prueba `test_cross_user_isolation` sirve como base reproducible. Para presentar una mejora como reto, crea una rama y añade una mejora concreta propia (por ejemplo, prueba de expiración de sesión), documenta antes/después y ejecuta la prueba. No presentar la función ya existente como una modificación posterior.
