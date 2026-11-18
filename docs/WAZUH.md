# Conectar Vigía con Anthwatch

Esta integración se entrega preparada, **no instalada ni validada en tus VMs**. Primero comprueba la aplicación y la conexión del agente existente. Haz copia de la configuración que vayas a editar. No sustituyas tus reglas SSH/portal anteriores.

## 1. Agente de anthwatch-server

Los logs existen tras arrancar la aplicación: `/opt/vigia/logs/events.jsonl`. Si usaste otra ruta, adapta el XML. El agente necesita permiso de lectura y recorrido del directorio; compruébalo con la identidad real del proceso. No uses chmod 777.

Añade el bloque de `wazuh/agent-localfile.xml` dentro del `<ossec_config>` existente en `/var/ossec/etc/ossec.conf`, sin borrar nada. Después reinicia y revisa el estado:

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 40 /var/ossec/logs/ossec.log
```

## 2. Manager anthwatch-wazuh

Se usa el decodificador JSON incorporado. No hace falta crear un decoder personalizado para estos campos.

Comprueba primero que no estén usados los IDs 110500–110511:

```bash
sudo grep -RE 'id="1105(0[0-9]|1[01])"' /var/ossec/etc/rules
```

Si hay coincidencias, asigna otro rango libre y actualiza también los if_sid. Copia `vigia_rules.xml` como archivo nuevo en `/var/ossec/etc/rules/vigia_rules.xml`; no sobrescribas local_rules.xml. Asigna permisos coherentes con los archivos existentes.

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logtest
```

Pega una línea de ejemplo SINTÉTICA:

```json
{"timestamp":"2026-11-17T12:00:00+00:00","app":"vigia","event":"validation_failed","srcip":"192.0.2.10","user_id":null,"fields":["name"]}
```

Resultado esperado: decoder JSON y regla 110503. Prueba asimismo `login_failed` (110501), `access_denied` (110502), `login_ok` (110504) y `csrf_denied` (110505), cambiando solo event. Son expectativas, no evidencias ya obtenidas. Si la validación falla, corrige o retira el nuevo archivo antes de reiniciar.

Cuando las pruebas sean correctas:

```bash
sudo systemctl restart wazuh-manager
```

## 3. Prueba de extremo a extremo

Desde el navegador realiza una entrada inválida que llegue al servidor, un único acceso fallido o una consulta a un ID ajeno con otra cuenta. Comprueba `events.jsonl`, después las alertas del manager y finalmente el dashboard filtrando por `rule.groups: vigia` y por tu agente. Ajusta el rango temporal.

No todos los rechazos generan la misma alerta: el bloqueo HTML del navegador no llega al servidor; el rechazo inicial por falta de cabecera X-Vigia-Request tampoco se registra como csrf_denied. Los eventos de nivel 3 son visibles solo si la configuración del manager acepta ese nivel. Un resultado 404 puede deberse a un ID inexistente y no a una intrusión.

No uses la IP observada como prueba de identidad: el túnel SSH o NAT pueden alterarla. Se registran IDs de usuario, no contraseñas, cookies, tokens ni cuerpos completos de formularios. Los logs rotan a 2 MB con tres copias; valida la ingesta durante rotación en tu entorno.

## Fuentes oficiales consultadas

- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
- https://documentation.wazuh.com/current/user-manual/ruleset/

V3 añade IDs 110506–110511 para límites, origen, cambio de contraseña, rechazo de cambio, revocación y error interno. Comprobar también estos IDs antes de instalar. Las reglas están preparadas, no validadas aún con el motor de tu Wazuh.

V6 añade IDs 110512–110515 para acceso administrativo denegado, cambios de acceso, revocación de sesiones y consulta administrativa de incidencias. Comprueba colisiones antes de instalar y valida con wazuh-logtest. Los eventos identifican al administrador en user_id y, para gestión de cuentas, al afectado en target_user_id. Estas reglas solo tienen comprobación de sintaxis XML aquí.
