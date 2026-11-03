# Cambios

## 0.3.1-rc.1

- Resumen con veredicto unico: SEGURA / REVISAR / EN RIESGO y una frase simple.
- Puertos: se descartan PID 0 y filas efimeras; cruce con la lista real de .NET.
- Puertos sensibles (PostgreSQL, MySQL, RDP, SMB, Docker...) abiertos a la red se marcan aparte.
- UPnP e IOC explican el motivo real cuando no se pueden completar.
- Tabla de red legible: acepta numero de fila o puerto; un error no borra la investigacion.
- Nueva comprobacion de UAC y aviso cuando se ejecuta como administrador.
- Deteccion de compilaciones Insider; un 404 del mes en curso de MSRC ya no cuenta como hueco.
- Exportaciones con contrasenas/tokens redactados.

## 0.3.0-rc.1

- Investigacion de procesos/puertos/rutas y reglas, con bloqueo reversible especifico.
- Router UPnP, soporte Microsoft, licencias ESU/LTSC, WUA y parches de seguridad elegidos.
- Correlacion KB/CVE MSRC y fuentes incompletas explicitas.
- Motor IOC Zero-Breach fijado, verificacion de hash y aislamiento temporal de Python.
- Salud antivirus WSC y prueba externa portable/importable.
- Cobertura avanzada pendiente visible; no se oculta borrando advertencias.



## 0.2.0-rc.2

- Men� legible con opciones en l�neas separadas, resumen general y detalle t�cnico separado.
- An�lisis de protecci�n, firmas, firewall y escuchas con niveles y propuestas; lagunas siempre visibles.
- Exportaci�n directa al Escritorio real: TXT legible y JSON del mismo diagn�stico, con advertencias e historial de acciones.
- Acciones Defender elegidas individualmente: firmas, an�lisis r�pido y activaci�n de protecci�n cuando corresponde; permisos y verificaci�n posterior expl�citos.
- Sin escaneo silencioso al exportar, sin elevaci�n autom�tica y sin presentar una solicitud de an�lisis como ausencia de infecci�n.


## 0.2.0-rc.1 — 2026-11-02

- Release candidata con diagnóstico, privacidad reversible y limpieza controlada de temporales antiguos.
- Lanzamiento sin temporales compartidos, resolución de intérpretes por PATH ni elevación automática.
- Plan y journal de privacidad con comprobación posterior, identidad, ACL y restauración que conserva cambios posteriores.
- Rutas locales, rechazo de enlaces/remotos, límite de inventario y revalidación antes de eliminar archivos.
- Diagnóstico ampliado de firewall efectivo, antivirus, escuchas, persistencia y apps; cobertura no disponible explícita.
- Exportación de informe a archivo nuevo, CI en dos motores y paquete reproducible con hashes.

Se retiran los flujos antiguos de desinstalación genérica, eliminación de servicios, exclusiones supuestamente huérfanas y vaciado manual de Windows Update. No se publica como versión estable hasta ampliar la validación en VMs.
