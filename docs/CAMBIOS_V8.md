# Selección y retirada de ejemplos · v8

Cargar casos de ejemplo abre un diálogo con los seis casos disponibles. Marca los que quieras y pulsa Cargar seleccionados. Los ya cargados aparecen deshabilitados; cada cuenta puede cargar el resto después. Solo se crean los dominios necesarios y se reutilizan los existentes. Se comprueban cuotas sobre las altas reales, sin reservar seis casos si solo eliges uno.

En el mismo diálogo, Quitar ejemplos de mi cuenta permite seleccionar los casos cargados que se quieren eliminar. Hay una confirmación explícita: la eliminación borra también todas sus notas, incluidas las añadidas por el usuario, y no se puede deshacer. Puedes volver a cargar el ejemplo original, pero no recupera tus modificaciones ni notas borradas. Los dominios se conservan y los casos personales no se borran.

La API exige sesión, CSRF, propiedad y el marcador interno creation_source=demo. Un título que empiece por [DEMO] no basta. La validación comprueba toda la selección antes de borrar y la operación es transaccional: si contiene un caso ajeno o personal, no se elimina ninguno. Los casos históricos sin marcador fiable de ejemplo no se ofrecen para borrar automáticamente. El administrador gestiona aquí únicamente sus ejemplos propios; no puede borrar los ajenos desde este selector.

Las instalaciones v4–v7 ya guardaban el origen demo. La migración incorpora una clave de catálogo a sus ejemplos reconocidos sin eliminar registros. La antigua tabla demo_loaded se conserva por compatibilidad, pero ya no bloquea cargas posteriores. Los ejemplos identificados como demo sin clave de catálogo siguen apareciendo en la lista de retirada. El catálogo se define por IDs estables del 1 al 6; no se deben reordenar sin migración.

GET /api/demo devuelve catálogo y ejemplos propios cargados. POST /api/demo recibe case_ids (1–6, sin repetidos). DELETE /api/demo recibe incident_ids (IDs concretos de ejemplos propios). Ambos requieren cabeceras de escritura y CSRF. Se registran eventos demo_loaded y demo_removed con cantidades, no textos ni credenciales.

37 pruebas automatizadas: selección parcial, idempotencia, recarga tras eliminar, eliminación de notas, conservación de dominios/casos personales, aislamiento entre cuentas, CSRF, rechazo atómico de selecciones mixtas y cuotas exactas, además de los controles anteriores. Sintaxis Python/JavaScript comprobada. Revisión visual del diálogo pendiente; no se ha desplegado en las máquinas del usuario.

Actualizar conservando .env y data/ o volumen Docker según ACTUALIZAR.md, reiniciar/reconstruir y recargar con Ctrl+Mayús+R. No hace falta crear otra cuenta.
