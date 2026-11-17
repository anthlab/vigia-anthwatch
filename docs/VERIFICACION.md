# Verificación de Vigía v3

Fecha: 17/11/2026. Entorno limpio Python 3.12, paquetes de requirements.lock y httpx 0.28.1 para pruebas.

| Verificación | Resultado | Evidencia/límite |
|---|---|---|
| unittest | 23 pruebas correctas | evidencias/pruebas.txt |
| pip-audit 2.10.1 | 13 dependencias, cero vulnerabilidades conocidas | evidencias/dependencias.json; fotografía temporal |
| Bandit 1.9.4 | Tres avisos bajos revisados | evidencias/bandit.json y SEGURIDAD.md |
| pip check | Sin dependencias incompatibles | Entorno limpio de pruebas |
| Sintaxis Python / JavaScript | Correcta | compileall / node --check |
| YAML de Compose | Bien formado | No equivale a construir/ejecutar Docker |
| Lanzador | Creación de .env y persistencia de clave probadas | Incluye regresión del fallo Path.open(opener) |
| Copia SQLite | Integridad, datos y eliminación de sesiones probados | Base mínima de prueba |
| Docker, TLS real, Wazuh | Pendientes en tus VMs | No disponibles aquí |
| Navegador completo v3 | Pendiente | El código del cliente se comprobó sintácticamente; API probada |

La revisión visual anterior de la pantalla de acceso no prueba los controles nuevos. Ningún caso [DEMO] se usa como evidencia real de estas verificaciones.
