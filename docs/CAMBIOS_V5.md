> Documento histórico de v5. Desde v6, admin sí tiene permisos globales; consulta ADMINISTRACION.md.

# Cuentas y bienvenida · v5

En el primer arranque se crea la cuenta inicial admin, con correo admin@vigia.test. La contraseña aleatoria se genera en ese equipo, se guarda con hash scrypt en SQLite y se entrega en data/admin-inicial.txt con permisos 600. No hay una contraseña universal dentro del ZIP. El registro público no permite elegir ese nombre si ya existe.

Para consultar las credenciales en ejecución local: `cat data/admin-inicial.txt`. En Docker: `docker compose exec web cat /app/data/admin-inicial.txt`. Inicia sesión con el correo; cambia la contraseña en Seguridad de la cuenta y elimina el archivo inicial. No compartas su contenido ni lo incluyas en capturas. El directorio data está excluido de Git. La contraseña inicial no se restaura al reiniciar. Si ya existía un usuario llamado admin, se conserva con su correo y contraseña originales. Si admin@vigia.test pertenece a otro nombre, el arranque avisa del conflicto y no sobrescribe la cuenta.

Admin es una cuenta inicial con datos privados, no un rol con permiso para consultar o modificar otras cuentas. No se añade un panel de administración global ni se relajan los controles de propietario.

El correo ya era único en la base, pero antes el registro respondía de forma genérica para no revelar si existía. Ahora devuelve 409 y un aviso explícito. El nombre de usuario también es único: se normalizan espacios exteriores, mayúsculas y variantes Unicode equivalentes (NFKC + casefold). La restricción y la transacción del servidor impiden carreras entre registros. El correo se compara tras quitar espacios y convertir a minúsculas, sin inventar equivalencias de proveedores como puntos o alias +.

La versión antigua permitía nombres repetidos. Al migrar, se conserva el primer nombre y se añade #ID a los posteriores en conflicto, manteniendo IDs, correos, contraseñas y datos. El acceso sigue siendo por correo. Este cambio de nombre no elimina ni fusiona cuentas.

La bienvenida explica dominios, incidencias, estadísticas y ejemplos ficticios. Se abre al entrar por primera vez en el panel y se registra inmediatamente en SQLite, mediante una petición autenticada con CSRF. Se conserva entre reinicios y navegadores. Cada cuenta anterior verá la bienvenida una vez tras actualizar. Si falla el guardado se muestra un error y podrá aparecer de nuevo; abrir simultáneamente dos pestañas por primera vez puede mostrarla en ambas.

La base y los logs usan por defecto rutas ancladas al directorio del proyecto, incluso si Uvicorn se inicia desde otra carpeta. DATA_DIR y LOG_DIR explícitos siguen teniendo prioridad. No se ha identificado la causa concreta del problema de guardado comunicado por el usuario: sigue pendiente conocer su modo de ejecución y revisar su entorno. Las pruebas comprueban persistencia con SQLite real.

Los avisos explícitos de duplicados permiten descubrir si una cuenta existe. Es una decisión funcional solicitada para el laboratorio; se mantienen los límites de registro. No se ha realizado una nueva auditoría de dependencias ni una revisión visual del navegador en esta versión.
