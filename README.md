# El Centinela de Windows 0.2.0-rc.2

![El Centinela de Windows](assets/og-image.png)

Release candidata usable de mantenimiento por usuario: diagnÃ³stico de seguridad, reducciÃ³n de sugerencias/publicidad con respaldo y deshacer, y limpieza de temporales antiguos con vista previa.

## Empezar

Descargar el ZIP de la release, extraerlo completo y abrir `El Centinela de Windows.bat`. Conservar `src` junto al BAT. Usa Windows PowerShell 5.1, sin instalar herramientas ni pedir administrador. Si una consulta exige mÃ¡s permisos, el informe muestra `Unavailable`; no significa que estÃ© todo bien.

1. **DiagnÃ³stico:** Defender, proveedores antivirus, firewall efectivo, escuchas TCP, tareas, servicios, apps y ajustes de publicidad. No modifica configuraciÃ³n.
2. **Privacidad:** vista previa, confirmaciÃ³n exacta, respaldo previo y comprobaciÃ³n de cada valor. Afecta esta cuenta; conservar las fotos de Spotlight. Windows puede restablecer ajustes en actualizaciones o por GPO/MDM. Puede requerir cerrar sesiÃ³n.
3. **Temporales:** solo archivos de Temp de esta cuenta, creados y modificados hace mÃ¡s de 14 dÃ­as; nunca borrado recursivo de carpetas. Omite enlaces y rechaza rutas remotas. Cerrar instaladores y aplicaciones primero. El borrado es permanente.
4. **Deshacer privacidad:** elegir el respaldo; conserva valores modificados despuÃ©s por otras apps. Respaldos locales bajo `%LOCALAPPDATA%/Centinela/State`, con acceso restringido.
5. **Exportar al Escritorio:** carpeta nueva con Resumen.txt y Diagnostico.json del último diagnóstico, incluidas advertencias y resultados de acciones. Usa el Escritorio real de Windows, incluso redirigido/OneDrive; puede sincronizarse. No vuelve a escanear ni sobrescribe informes.
6. **Detalle técnico:** consultar el inventario completo cuando haga falta.
7. **Soluciones:** propuestas según los hallazgos. Actualizar firmas, solicitar análisis rápido o activar protección en tiempo real (requiere sesión elevada) cuando Defender está en modo Normal; confirmación individual y comprobación posterior. Firewall y cambios sensibles reciben instrucciones específicas.

## Seguridad y lÃ­mites

Ejecutar desde la sesiÃ³n habitual de la cuenta a mantener. No desinstala antivirus, apps, servicios o drivers; no cambia reglas de firewall, RDP, cifrado ni polÃ­ticas empresariales. Esas operaciones requieren validaciones adicionales y se conservan como tareas guiadas desde Windows.

La detecciÃ³n de proveedores antivirus no prueba su salud. Una escucha local no demuestra exposiciÃ³n a Internet. No certifica ausencia de compromiso, no comprueba todas las CVE/ESU/LTSC y no incluye aÃºn el motor opcional Zero-Breach-Toolkit. Las consultas de Windows no constituyen aislamiento de red.

Esta es una **prerelease**, no una versiÃ³n estable certificada en toda combinaciÃ³n de hardware/ediciÃ³n. Ver [validaciÃ³n y lÃ­mites](docs/SECURITY-CANDIDATE.md) y [cambios](CHANGELOG.md).

## Desarrollo y validaciÃ³n

Pruebas aisladas en Windows PowerShell 5.1 y PowerShell 7: `tests/security.tests.ps1`. Prueban registro simulado y archivos/ACL/enlaces reales exclusivamente dentro de fixtures descartables. El uso normal sigue utilizando PowerShell 5.1. Empaquetado reproducible: `python build/package.py DESTINO`.

## Licencia y autor

[MIT](LICENSE). Rodolfo AgustÃ­n GarcÃ­a ([@ragustingarcia](https://github.com/ragustingarcia)) â€” [ragustingarcia.com](https://ragustingarcia.com/).
