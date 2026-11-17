"""Contenido ficticio. No contiene cuentas, credenciales ni evidencia real."""
CASES = [
 ('empresa.test','Correo que solicita restablecer la contraseña','phishing','alta','investigacion',
  'Un empleado comunica un correo con urgencia para cambiar su contraseña. El enlace no coincide con el dominio esperado. Aún no se ha confirmado si introdujo datos.',
  ['Se conserva una copia ficticia del mensaje para la práctica. No se abren enlaces.', 'Pendiente: contrastar remitente, cabeceras y relato del usuario antes de concluir compromiso.']),
 ('portal.test','Acceso comunicado fuera del horario habitual','acceso','alta','pendiente',
  'Una cuenta de laboratorio presenta un acceso a las 02:15 UTC en el escenario simulado. Puede ser una actividad legítima; requiere confirmación.',
  ['Pendiente de consultar al titular y contrastar registros. La hora por sí sola no confirma una intrusión.']),
 ('tienda.test','Formulario con entradas incorrectas','otro','baja','resuelta',
  'Durante una revisión manual se enviaron valores vacíos y un dominio mal formado. La aplicación rechazó las entradas.',
  ['Resultado ficticio del caso de ejemplo: respuesta de validación y ningún registro nuevo.', 'Cierre del ejemplo: control de validación satisfactorio. No se considera vulnerabilidad.']),
 ('empresa.test','Equipo con comportamiento inusual','equipo','media','investigacion',
  'Un usuario describe lentitud y ventanas inesperadas en un equipo de pruebas. No hay evidencia suficiente para afirmar infección.',
  ['Registrar síntomas y hora aproximada. Pendiente de revisar procesos, software instalado y alertas del equipo.']),
 ('portal.test','Consulta de un recurso de otra cuenta','acceso','media','resuelta',
  'En el escenario didáctico, una cuenta B solicita una incidencia creada por A y recibe un rechazo.',
  ['Ejemplo de control de permisos: el servidor no devuelve el contenido ajeno.', 'Cerrar como acceso denegado por el control. No implica que se haya filtrado información.']),
 ('tienda.test','Revisión de disponibilidad del portal','otro','media','pendiente',
  'Se comunica una interrupción temporal de servicio en una tienda ficticia. Falta determinar duración, alcance y causa.',
  ['Pendiente: comprobar health, estado del contenedor y registros. No se ha realizado ningún escaneo.'])
]

def seed_demo(con, user_id):
    if con.execute('SELECT 1 FROM demo_loaded WHERE user_id=?',(user_id,)).fetchone(): return 0
    for domain,title,category,priority,status,description,notes in CASES:
        con.execute('INSERT OR IGNORE INTO domains(user_id,name) VALUES(?,?)',(user_id,domain))
        did=con.execute('SELECT id FROM domains WHERE user_id=? AND name=?',(user_id,domain)).fetchone()['id']
        iid=con.execute('INSERT INTO incidents(user_id,domain_id,title,description,category,priority,status) VALUES(?,?,?,?,?,?,?)',
            (user_id,did,'[DEMO] '+title,'CASO FICTICIO · No es evidencia real.\n\n'+description,category,priority,status)).lastrowid
        for body in notes:
            con.execute('INSERT INTO notes(incident_id,body) VALUES(?,?)',(iid,'[SIMULACIÓN] '+body))
    con.execute('INSERT INTO demo_loaded VALUES(?)',(user_id,))
    return len(CASES)
