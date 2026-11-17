# Primera prueba · Vigía v3

Si ya tienes una cuenta y datos, lee ACTUALIZAR.md antes de extraer encima de tu proyecto. Conserva la carpeta anterior y no copies su .venv.

Desde la nueva carpeta vigia:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python iniciar.py
```

Abre http://localhost:8000. Crea una cuenta ficticia con una frase de contraseña de al menos 15 caracteres y después inicia sesión. Si copiaste la carpeta data de tu versión anterior, entra con tu cuenta existente. El lanzador ya tiene corregido el fallo Path.open(opener=...).

## Qué encontrarás

| Caso [DEMO] | Dominio | Prioridad | Estado |
|---|---|---|---|
| Correo que solicita restablecer la contraseña | empresa.test | Alta | En investigación |
| Acceso comunicado fuera del horario habitual | portal.test | Alta | Pendiente |
| Formulario con entradas incorrectas | tienda.test | Baja | Resuelta |
| Equipo con comportamiento inusual | empresa.test | Media | En investigación |
| Consulta de un recurso de otra cuenta | portal.test | Media | Resuelta |
| Revisión de disponibilidad del portal | tienda.test | Media | Pendiente |

Los casos contienen notas [SIMULACIÓN] y son editables. No se consultan dominios reales. Las cuentas antiguas pueden cargar los ejemplos con el botón correspondiente sin borrar sus incidencias.

Abre un caso, añade una nota y cambia el estado. Recarga y comprueba que se conserva. En Seguridad de la cuenta puedes cambiar tu contraseña (exige la actual) o cerrar las sesiones. El cambio requiere volver a entrar.

Si ves 429, espera el tiempo indicado. La sesión caduca tras 15 minutos sin peticiones autenticadas o una hora total. Iniciar sesión en otra ventana con la misma cuenta revoca la sesión anterior: para probar dos propietarios usa dos cuentas distintas.

Para parar: Ctrl+C. Para volver: activa .venv y ejecuta python iniciar.py. Para editar con recarga usa --dev. No reinstales dependencias en cada arranque.

El informe de seguridad está en docs/SEGURIDAD.md y los resultados de pruebas en docs/evidencias. Docker y Wazuh se prueban después en el laboratorio; estos ejemplos no sustituyen las evidencias de la sesión 1.
