# Cambios

## 0.2.0-rc.1 — 2026-11-02

- Release candidata con diagnóstico, privacidad reversible y limpieza controlada de temporales antiguos.
- Lanzamiento sin temporales compartidos, resolución de intérpretes por PATH ni elevación automática.
- Plan y journal de privacidad con comprobación posterior, identidad, ACL y restauración que conserva cambios posteriores.
- Rutas locales, rechazo de enlaces/remotos, límite de inventario y revalidación antes de eliminar archivos.
- Diagnóstico ampliado de firewall efectivo, antivirus, escuchas, persistencia y apps; cobertura no disponible explícita.
- Exportación de informe a archivo nuevo, CI en dos motores y paquete reproducible con hashes.

Se retiran los flujos antiguos de desinstalación genérica, eliminación de servicios, exclusiones supuestamente huérfanas y vaciado manual de Windows Update. No se publica como versión estable hasta ampliar la validación en VMs.
