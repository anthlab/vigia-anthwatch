# Verificación vigente · v8

37 pruebas: evidencias/pruebas-v8.txt. Nuevos escenarios descritos en CAMBIOS_V8.md. Sintaxis Python y JavaScript comprobada; revisión visual pendiente. Resultados históricos a continuación.

---

# Verificación vigente · v7

34 pruebas superadas: evidencias/pruebas-v7.txt. Registro y admin nuevos sin datos demo, carga manual e idempotencia, aislamiento y permisos. Sintaxis JavaScript comprobada. La ruta inicial por rol se revisó en código; revisión visual pendiente. Los apartados siguientes conservan resultados históricos.

---

# Verificación vigente · v6

34 pruebas en evidencias/pruebas-v6.txt. Comprobaciones nuevas detalladas en ADMINISTRACION.md. Python/JavaScript y XML de Wazuh comprobados sintácticamente. No se ha repetido auditoría de dependencias ni revisión visual. Los resultados siguientes son históricos.

---

# Verificación vigente · v5

Resultado y pruebas nuevas: evidencias/pruebas-v5.txt (30 pruebas). Se comprueban admin persistente y credenciales privadas, nombres únicos normalizados, duplicados de correo, bienvenida por cuenta entre reinicios y migración de nombres antiguos repetidos. Sintaxis Python y JavaScript comprobada. Entorno Python 3.12 disponible en el ejecutor; esta ejecución no implica una instalación limpia de dependencias ni un despliegue en las VMs del usuario.

No se ha repetido auditoría de dependencias, Bandit ni revisión visual en v5. El resto de este documento conserva los resultados históricos y sus límites.

---

# Verificación de Vigía v4

Fecha: 17/11/2026. Entorno limpio Python 3.12, paquetes de requirements.lock y httpx 0.28.1 para pruebas.

| Verificación | Resultado | Evidencia/límite |
|---|---|---|
| unittest | 26 pruebas correctas | evidencias/pruebas.txt |
| pip-audit 2.10.1 | 13 dependencias, cero vulnerabilidades conocidas | evidencias/dependencias.json; fotografía temporal |
| Bandit 1.9.4 (v3, no repetido en v4) | Tres avisos bajos revisados | evidencias/bandit.json y SEGURIDAD.md |
| pip check | Sin dependencias incompatibles | Entorno limpio de pruebas |
| Sintaxis Python / JavaScript | Correcta | compileall / node --check |
| YAML de Compose | Bien formado | No equivale a construir/ejecutar Docker |
| Lanzador | Creación de .env y persistencia de clave probadas | Incluye regresión del fallo Path.open(opener) |
| Copia SQLite | Integridad, datos y eliminación de sesiones probados | Base mínima de prueba |
| Docker, TLS real, Wazuh | Pendientes en tus VMs | No disponibles aquí |
| Navegador completo v4 | Pendiente | El código del cliente se comprobó sintácticamente; API probada |

La revisión visual anterior de la pantalla de acceso no prueba los controles nuevos. Ningún caso [DEMO] se usa como evidencia real de estas verificaciones.

Actualización v4 preparada el 18/11/2026. La ejecución de las 26 pruebas se realizó durante esta modificación, antes de la interrupción de la sesión. Incluye atribución de autor/editor, rechazo de autor falsificado, casos de sistema y migración de históricos sin inventar autores. Los informes de dependencias y Bandit corresponden a la revisión v3 del 17/11/2026; no se presentan como un análisis nuevo del código v4.

La vista previa no pudo abrirse: la revisión automática del navegador rechazó la operación por límite de uso. Pendiente comprobar visualmente en portátil/móvil, zoom y listas largas.
