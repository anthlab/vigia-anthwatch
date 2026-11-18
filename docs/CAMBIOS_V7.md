# Inicio por rol y ejemplos opcionales · v7

Al iniciar sesión o recuperar la sesión al recargar, admin entra directamente en Administración, con estadísticas globales y gestión de usuarios. Los usuarios normales entran en Mi panel, con sus propios dominios, incidencias y contadores. Admin mantiene Mi panel para sus casos personales y el menú Incidencias globales para la consulta transversal.

Las cuentas nuevas, incluida una nueva cuenta admin, empiezan sin dominios ni incidencias. Cargar casos de ejemplo sigue disponible en Mi panel: añade los tres dominios y seis casos ficticios una sola vez por cuenta. La carga manual sigue comprobando sesión, CSRF y cuotas, y no mezcla datos de distintas cuentas.

Esta actualización no elimina datos: las cuentas anteriores conservan sus casos reales y sus ejemplos. Si ya tenían los seis ejemplos, seguirán apareciendo. No se borran ni se reinicia la marca de ejemplos cargados.

La bienvenida distingue el inicio administrativo del personal y explica la carga opcional. Su marca de primera visita se conserva; no vuelve a abrirse para cuentas que ya la vieron.

Validación: 34 pruebas superadas, incluidos registro vacío, admin nuevo vacío, carga manual idempotente, aislamiento de cuentas y permisos administrativos. Sintaxis de JavaScript comprobada. El cambio de pantalla inicial se revisó en código; no se ha hecho una nueva comprobación visual ni despliegue en las VMs del usuario.

Actualizar: conserva .env y data/ o tu volumen Docker siguiendo ACTUALIZAR.md. Reinicia o reconstruye el contenedor y recarga el navegador con Ctrl+Mayús+R. No necesitas borrar la base ni crear otra cuenta.
