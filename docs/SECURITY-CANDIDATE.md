# Candidata de seguridad: alcance y validación

Esta entrega implementa la contención inicial del plan de auditoría del 30/10/2026. Es una candidata de diagnóstico, pendiente del ejecutor transaccional y de validación en VMs. No es la actualización funcional completa del plan de siete entregas.

El BAT usa el PowerShell del sistema por ruta absoluta, restringe la búsqueda de módulos al directorio de Windows y ejecuta `src/Centinela.ps1` sin extracción temporal ni elevación automática. Distribuir ambos archivos conservando su estructura. El diagnóstico puede quedar incompleto por falta de permisos y se informa como tal en los inventarios corregidos.

Las acciones están deshabilitadas por defecto sin interruptor público para reactivarlas. Se retiraron la ejecución genérica de desinstaladores del registro, la eliminación de servicios, la limpieza de exclusiones basada en existencia y el borrado manual de descargas de Windows Update. Los antivirus no se ofrecen como limpieza ordinaria. Solicitar un scan ya no se anuncia como resultado limpio/completado.

La confirmación requiere respuesta completa; cancelar o escribir salir no autoriza acciones. El reporte restaura su estado anterior de solo lectura. Los errores de inventario de programas y Appx se declaran incompletos. Quedan lectores heredados que aún necesitan el contrato de cobertura por comprobación del siguiente PR.

## Pruebas

Ejecutar `powershell.exe -NoProfile -File tests/security.tests.ps1` y `pwsh.exe -NoProfile -File tests/security.tests.ps1`. Se cargan definiciones mediante `-LibraryOnly`; procesos y mutaciones probados están interceptados. No ejecutan limpieza ni cambios de configuración. CI repite estos controles en ambos motores.

Pendiente antes de activar modificaciones: acciones tipadas, identidad y ámbito, guardia de rutas, journal con ACL, respaldo y reversión, verificación posterior, catálogos compatibles y pruebas VM con UAC/reinicios/Appx/Defender. También faltan los módulos ampliados de seguridad y la integración opcional de Zero-Breach.

No se declara ausencia de compromiso ni eficacia completa de detección. Una firma digital o un inventario sin resultados no constituyen por sí solos un dictamen de seguridad.
