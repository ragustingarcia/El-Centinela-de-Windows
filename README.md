# El Centinela de Windows 0.3.0-rc.1

Mantenimiento y seguridad de Windows por usuario. Extraer el ZIP completo y abrir El Centinela de Windows.bat. Requiere PowerShell 5.1; el menu normal no pide administrador.

## Uso

1. Diagnostico general: resumen interpretado e inventario. Los controles avanzados pendientes cuentan como sin comprobar.
2. Publicidad: vista previa, respaldo, verificacion y deshacer de nueve preferencias por usuario.
3. Temporales: archivos creados y modificados hace mas de 14 dias, vista previa y revalidacion, sin eliminar carpetas recursivamente. Borrado permanente.
4. Deshacer privacidad: conserva cambios posteriores ajenos.
5. Exportar al Escritorio real: TXT legible y JSON con el mismo diagnostico, advertencias, evidencias y resultados.
6. Detalle tecnico.
7. Soluciones: elegir una propuesta ejecuta su investigacion o accion, con confirmacion. Las escuchas abren investigacion de procesos/puertos y permiten proponer bloqueo reversible.
8. Seguridad avanzada: elegir comprobaciones locales u online y acciones concretas.

## Seguridad avanzada

- Red: procesos, ejecutables, puertos, rutas, adaptadores VPN y reglas efectivas. Bloqueo entrante por programa/puerto identificado; preserva puertos de sistema y administracion remota. UAC eleva solo la accion y exige misma cuenta. Se registra antes de crear regla y puede deshacerse desde el menu. La aplicacion puede seguir escuchando aunque el firewall bloquee trafico.
- Router: consulta de mapeos UPnP sin cambiarlos. Si el router no los publica, registra cobertura pendiente. Redirecciones manuales y administracion remota necesitan su interfaz y credenciales; no se inventa una auditoria completa.
- Windows Update: consulta explicita al origen configurado; muestra parches/KB y reinicio pendiente. Instalacion elegida de parches de seguridad: revalida IDs/categoria, acepta las EULA tras confirmacion, descarga e instala sin reiniciar automaticamente. Los resultados parciales o pendientes no se anuncian como resueltos.
- Soporte: consulta tabla oficial de Microsoft para version/edicion reconocida y licencias ESU detectadas. Canal LTSC/no reconocido o pagina que cambio permanece Unknown, con evidencia para revisar.
- CVE: correlacion de KB pendientes con CVRF Microsoft de los ultimos tres meses; registra fuentes fallidas. No equivale a catalogar todas las vulnerabilidades de cada aplicacion o firmware.
- Salud antivirus: API Windows Security Center ademas del estado Defender. Es salud informada por proveedores, no un ataque de prueba contra el antivirus.
- IOC: Zero-Breach-Toolkit incluido a commit/hash fijos, con sus licencias. Requiere Python instalado en Programs/Python de esta cuenta. Aisla ese python.exe mediante bloqueo saliente temporal del firewall (UAC), ejecuta el escaner y retira la regla (otro UAC). Puede afectar otros procesos Python. Si se interrumpe, retirar reglas Centinela-IOC desde Firewall. El bloqueo de Python no es una sandbox total de todos los servicios/subprocesos del sistema. No se visitan indicadores para validarlos.
- Exposicion externa: tools/ExternalProbe.ps1 se ejecuta en otra PC fuera de la LAN/VPN, contra TU IP publica y puertos autorizados. Importar su JSON en opcion 8. Se conserva alcance/fecha y procedencia declarada, sin fingir una comprobacion externa desde dentro de la red.

## Privacidad y alcance

Informes y artefactos IOC contienen datos privados; el Escritorio puede sincronizarse por OneDrive. No se suben informes automaticamente. Las consultas online se confirman antes y pueden revelar la IP al proveedor. Ante indicios serios, preservar evidencia; no limpiar ni borrar automaticamente archivos sospechosos.

Es prerelease. Ver docs/SECURITY-CANDIDATE.md para pruebas y pendientes. No garantiza ausencia de compromiso. Incluye MIT para Centinela; el motor tercero conserva Apache-2.0 y sus conjuntos de indicadores mantienen sus propias condiciones.

Autor: Rodolfo Agustin Garcia - https://ragustingarcia.com/.
