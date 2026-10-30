# El Centinela de Windows

![El Centinela de Windows](./assets/og-image.png)

**Candidata de diagnóstico y revisión de seguridad.** Revisa arranque, Defender, publicidad, programas, espacio y apps de la Tienda. Esta versión mantiene las modificaciones deshabilitadas mientras se incorpora un ejecutor con verificación y recuperación.

## Uso

1. Descargar el ZIP y extraerlo completo, conservando `src` junto al BAT.
2. Abrir `El Centinela de Windows.bat`. Utiliza Windows PowerShell 5.1 sin instalar herramientas ni solicitar elevación automática.
3. Elegir el reporte o una categoría. Las consultas que no dispongan de permisos pueden quedar incompletas.

El BAT ya no es un archivo autónomo: requiere `src/Centinela.ps1`. No copiar únicamente el lanzador. Revisar la procedencia de la descarga y las advertencias de Windows antes de ejecutar.

## Alcance de esta candidata

- Lanzamiento mediante ruta absoluta, sin código temporal compartido.
- Sin ejecución de comandos de desinstalación tomados del registro.
- Sin eliminación de servicios, exclusiones de Defender o descargas de Windows Update.
- Confirmaciones exactas y tratamiento explícito de inventarios no disponibles.
- Pruebas aisladas en PowerShell 5.1 y 7; el uso real de todos los lectores en ambos motores todavía requiere validación en VMs.

El diagnóstico no certifica ausencia de ataques o vulnerabilidades. No sustituye antivirus, actualizaciones ni una investigación de incidentes.

Ver [alcance y trabajo pendiente](docs/SECURITY-CANDIDATE.md). Las funciones de limpieza y endurecimiento del plan se habilitarán por entregas después de su validación.

## Validación

`tests/security.tests.ps1` contiene comprobaciones con operaciones simuladas. El workflow repite esas comprobaciones en Windows PowerShell y PowerShell 7. No ejecuta limpiadores reales sobre el runner.

## Licencia y autor

[MIT](LICENSE). Rodolfo Agustín García ([@ragustingarcia](https://github.com/ragustingarcia)) — [ragustingarcia.com](https://ragustingarcia.com/).
