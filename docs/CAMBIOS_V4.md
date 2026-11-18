# Panel personal y autoría · v4

Cada cuenta conserva sus dominios, incidencias, notas y contadores. La API filtra por el usuario autenticado y rechaza lecturas y modificaciones ajenas. Los ejemplos iniciales son copias privadas, por eso dos cuentas nuevas pueden parecer iguales. La vista general incluye ahora el nombre de la cuenta y vuelve a ella al iniciar sesión; se limpia el filtro anterior.

La zona de trabajo ocupa la altura de la ventana. Dominios, incidencias y últimas incidencias tienen desplazamiento interno cuando el contenido desborda, encabezados fijos y acceso por teclado. La lista de últimas incidencias ya no corta a cinco registros. Se retiran las dos tarjetas de instrucciones inferiores para dedicar el espacio a los casos. Las tablas pueden desplazarse horizontalmente en pantallas estrechas; los diálogos y las notas también admiten desplazamiento.

En nuevas incidencias se guarda el creador desde la sesión del servidor. Cambiar el estado o añadir una nota registra el último editor y la fecha; las notas guardan su autor. Estos campos no son editables ni se aceptan desde el formulario. Las fechas se guardan en UTC y se presentan en la zona horaria del navegador. Los ejemplos nuevos muestran Sistema · ejemplo; no se atribuyen al usuario como si los hubiera escrito.

La migración conserva los registros existentes y deja su autoría desconocida. No se reconstruyen autores a partir de títulos ni se inventa historial. Se conserva el último editor, no un historial completo de todas las ediciones. Al ser cuentas privadas, normalmente el creador y el editor son la misma persona; esta versión no introduce equipos ni acceso compartido.

Verificación: 26 pruebas automatizadas superadas, incluidas aislamiento entre cuentas, atribución, rechazo de campos de autor falsificados y migración idempotente. JavaScript y Python pasan comprobación de sintaxis. La validación visual del tamaño y desplazamiento sigue pendiente por el bloqueo de la vista previa; no se ha desplegado esta actualización en el equipo del usuario.
