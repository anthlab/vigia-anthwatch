> Desde v7, admin entra directamente en Administración. Las cuentas nuevas empiezan vacías y la carga de ejemplos es opcional.

# Administración · v6

Admin pasa a ser un rol real, comprobado en el servidor en cada petición. Los registros públicos siempre nacen como usuarios normales. En una instalación nueva la cuenta inicial admin tiene rol admin; al actualizar desde v5 se asigna el rol una sola vez a la cuenta cuyo nombre normalizado es admin, conservando contraseña, correo y datos. Si habías creado esa cuenta manualmente antes de v5, revisa quién controla sus credenciales antes de actualizar. No se promociona a ninguna otra cuenta.

| Función | Usuario normal | Administrador |
|---|---|---|
| Panel personal y edición de casos propios | Sí | Sí |
| Estadísticas de todas las cuentas | No | Sí |
| Listar usuarios, correos, estado y número de activos/casos | No | Sí |
| Activar o desactivar usuarios normales | No | Sí |
| Cerrar sesiones de usuarios normales | No | Sí |
| Consultar incidencias y notas de todas las cuentas | No | Sí, solo lectura |
| Cambiar roles, borrar cuentas o leer contraseñas | No | No |

El menú Administración muestra contadores globales y la lista de usuarios. Desactivar bloquea el acceso y elimina las sesiones existentes, manteniendo los datos. Activar permite volver a iniciar sesión; no restaura sesiones revocadas. Cerrar sesiones obliga a autenticarse de nuevo. Las cuentas administradoras están protegidas contra desactivación o revocación desde esa lista; usa Seguridad de la cuenta para tus propias sesiones.

Incidencias globales muestra páginas de 50 registros y permite abrir una ficha de solo lectura con propietario, autor, último editor, fechas, estado, prioridad y notas. El panel personal continúa mostrando solo los casos propios. Los formularios de creación y edición siguen comprobando la propiedad del recurso.

Los permisos se leen de SQLite en cada petición. Ocultar el menú no es la protección: las rutas /api/admin requieren sesión activa y rol admin. Las escrituras requieren CSRF y validación estricta; un registro con role añadido se rechaza. Las respuestas nunca incluyen hashes de contraseñas ni tokens. Login y sesiones comprueban active; se vuelve a comprobar al emitir una sesión para reducir carreras con desactivaciones. Una petición ya autorizada y en curso puede terminar durante una revocación.

La bienvenida y el pie informan de la consulta administrativa. Se registran accesos administrativos denegados, cambios de acceso, revocaciones y apertura de fichas globales. Los eventos no son un registro inmutable: conserva las evidencias externamente con Wazuh si necesitas esa garantía. Se incluyen reglas 110512–110515, pendientes de validación en el motor de Wazuh del usuario.

Actualizar: conserva .env y la base de datos siguiendo ACTUALIZAR.md, reinicia el proceso o reconstruye el contenedor y vuelve a entrar con la cuenta admin. No hace falta volver a crearla. Si una sesión ya estaba abierta, recarga con Ctrl+Mayús+R para cargar el nuevo menú.

Verificación: 34 pruebas de API/operación, incluidas rechazo a usuarios normales, bloqueo de escalada mediante registro, lectura global sin ampliar las rutas personales, CSRF administrativo, desactivación con revocación, reactivación conservando datos y migración del rol. La revisión visual de estas pantallas y la prueba en Docker/Wazuh quedan pendientes; no se han desplegado los cambios en las máquinas del usuario.
