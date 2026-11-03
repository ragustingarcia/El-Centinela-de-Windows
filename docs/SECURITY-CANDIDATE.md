# Validacion y limites de 0.3.0-rc.1

Esta candidata amplia las funciones de rc.2 con investigacion de red, reglas reversibles, WUA, soporte online, licencias, CVRF y motor IOC fijado. Las comprobaciones aun no ejecutadas, denegadas, desconocidas o incompletas se muestran como pendientes; no se reemplazan por mensajes favorables.

La verificacion automatizada usa registro/Defender/WUA/firewall/red simulados y fixtures de archivos, ACL y enlaces reales. Incluye rechazo de procesos/puertos protegidos, cambio de ejecutable, journal previo, seleccion de parches modificada, descarga parcial, reinicio pendiente e informes IOC/externos desconocidos. El contrato --describe del motor generado se consulta sin realizar un escaneo privado.

CI valida lectura nativa del helper, SID distinto rechazado y creacion/deshacer de una regla sobre un listener loopback en un runner descartable. Esto verifica el objeto/regla, no alcanzabilidad desde Internet.

Pendiente antes de considerar estable: consentimiento UAC de extremo a extremo, efecto de reglas desde otra red, instalacion real de parches, aislamiento de red observado con captura, analisis IOC completo en una VM descartable, router real y prueba desde otra conexion. No se cambiaron firewall, antivirus ni actualizaciones de la PC de trabajo durante el desarrollo. Sin estas pruebas no se afirma que la candidata haya resuelto vulnerabilidades del equipo del usuario.

El motor se genera desde interplains/Zero-Breach-Toolkit commit ebc50fb160cebc6063c1164e670e3503d01a9613, sin cambios de codigo. Ver third_party/zero-breach/PROVENANCE.json, LICENSE, NOTICE e IOCS-LICENSE.md. El wrapper verifica SHA-256 antes de ejecutarlo. Necesita Python existente y no lo descarga automaticamente.

La regla temporal bloquea red para ese python.exe, no para todos los servicios/subprocesos que Windows pueda usar. Si el proceso se interrumpe o se cancela el permiso de limpieza, puede quedar la regla Centinela-IOC; se debe retirar en Firewall. Esto debe validarse en VM antes de promocionar el aislamiento a funcion estable.

Las fuentes de soporte y MSRC pueden cambiar. Un documento no reconocido se mantiene Unknown; la correlacion CVE es por KB pendientes y solo tres meses de boletines, con fuentes fallidas visibles. ESU/LTSC requiere comprobar el periodo y producto concretos; detectar una licencia no certifica su vigencia.

La prueba externa importada no esta firmada ni autentica la ubicacion desde la que se ejecuto. Reachable acredita que el cliente de prueba pudo conectar a esa IP/puerto/fecha declarados; no demuestra por si solo vulnerabilidad. NoConnection/Error no acreditan seguridad global. El usuario debe confirmar que la prueba se hace fuera de su LAN/VPN y contra su propia IP.

El helper elevado solo acepta acciones enumeradas, SID coincidente y parametros acotados; restringe PSModulePath y no ejecuta comandos del registro ni codigo del JSON. Como cualquier aplicacion local, no es una defensa contra un atacante que ya controla la misma cuenta/administrador y cambia sus archivos entre comprobaciones.
