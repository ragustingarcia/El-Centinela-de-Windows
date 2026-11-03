# Validación de 0.2.0-rc.1

Release candidata funcional del 02/11/2026. Lanzador sin elevación automática ni archivos ejecutables temporales. Las acciones implementadas son ajustes de publicidad HKCU y limpieza de archivos antiguos del Temp de la cuenta actual.

Privacidad: catálogo fijo de nueve valores DWORD, vista previa, rechazo de tipos desconocidos, respaldo antes de escribir, journal por acción, lectura posterior y restauración del valor original o de su ausencia. El journal enlaza SID y máquina; las rutas de registro no se toman del JSON. Deshacer conserva cambios posteriores ajenos y permite reintentar una restauración incompleta.

Temporales: destino fijo derivado de LocalApplicationData, unidad local, rutas canónicas y rechazo de reparse points en ancestros; antigüedad de creación/modificación superior a 14 días, máximo 10000 elementos, vista previa y revalidación de tamaño/fechas antes de borrar. No se eliminan carpetas. Los archivos bloqueados o cambiados se omiten con aviso. No existe rollback de este borrado.

Reportes: error de consulta distinto de inventario vacío; JSON opcional sin subida automática y sin sobrescribir archivos. El informe incluye datos sensibles. Los servicios de Windows consultados pueden realizar actividad de red; esto no es un análisis estrictamente offline.

## Evidencia

35 casos iniciales por motor pasaron en PowerShell 5.1.26100.9818 y 7.6.9. Incluyen aplicación/lectura posterior/restauración con registro simulado, fallo de respaldo, fallo de escritura, cambios concurrentes, journal de otra identidad y destinos arbitrarios; eliminación real de archivos de prueba, preservación de recientes, rechazo de destinos externos, ACL y junction real. Pruebas de exportación y catálogo de comprobaciones añadidas al cierre de release; los JSON de validación y CI registran el conteo final.

Ningún ajuste real de la máquina de trabajo se modificó. Junctions y ACL se verificaron con ejecución ampliada sobre carpetas descartables del repositorio. No se dispone de prueba completa en VMs de Home/Pro, hardware ARM64, cambios reales de publicidad tras reinicio o escenarios de instalación/servicing en curso. Por eso la publicación se marca prerelease.

## Riesgos residuales y alcance posterior

La comprobación de rutas reduce selecciones erróneas y redirecciones, pero no es una sandbox frente a un administrador o proceso del mismo usuario que cambie archivos entre comprobación y borrado. Usar sobre una sesión controlada; ante sospecha de intrusión, preservar evidencias y no limpiar.

Los toggles de publicidad son preferencias por usuario y no garantizan aplicación/persistencia en todas las builds o frente a políticas administradas. Un valor verificado significa que el registro quedó en el valor esperado, no prueba visual de toda publicidad eliminada.

Pendientes fuera de esta release: desinstaladores con adaptadores confiables, catálogo Appx exacto, endurecimiento avanzado de seguridad, cobertura de parches/soporte y adaptador opcional IOC de Zero-Breach. El diagnóstico no es una prueba de ausencia de brechas.
