# Validaci贸n de 0.2.0-rc.1

Release candidata funcional del 02/11/2026. Lanzador sin elevaci贸n autom谩tica ni archivos ejecutables temporales. Las acciones implementadas son ajustes de publicidad HKCU y limpieza de archivos antiguos del Temp de la cuenta actual.

Privacidad: cat谩logo fijo de nueve valores DWORD, vista previa, rechazo de tipos desconocidos, respaldo antes de escribir, journal por acci贸n, lectura posterior y restauraci贸n del valor original o de su ausencia. El journal enlaza SID y m谩quina; las rutas de registro no se toman del JSON. Deshacer conserva cambios posteriores ajenos y permite reintentar una restauraci贸n incompleta.

Temporales: destino fijo derivado de LocalApplicationData, unidad local, rutas can贸nicas y rechazo de reparse points en ancestros; antig眉edad de creaci贸n/modificaci贸n superior a 14 d铆as, m谩ximo 10000 elementos, vista previa y revalidaci贸n de tama帽o/fechas antes de borrar. No se eliminan carpetas. Los archivos bloqueados o cambiados se omiten con aviso. No existe rollback de este borrado.

Reportes: error de consulta distinto de inventario vac铆o; JSON opcional sin subida autom谩tica y sin sobrescribir archivos. El informe incluye datos sensibles. Los servicios de Windows consultados pueden realizar actividad de red; esto no es un an谩lisis estrictamente offline.

## Evidencia

35 casos iniciales por motor pasaron en PowerShell 5.1.26100.9818 y 7.6.9. Incluyen aplicaci贸n/lectura posterior/restauraci贸n con registro simulado, fallo de respaldo, fallo de escritura, cambios concurrentes, journal de otra identidad y destinos arbitrarios; eliminaci贸n real de archivos de prueba, preservaci贸n de recientes, rechazo de destinos externos, ACL y junction real. Pruebas de exportaci贸n y cat谩logo de comprobaciones a帽adidas al cierre de release; los JSON de validaci贸n y CI registran el conteo final.

Ning煤n ajuste real de la m谩quina de trabajo se modific贸. Junctions y ACL se verificaron con ejecuci贸n ampliada sobre carpetas descartables del repositorio. No se dispone de prueba completa en VMs de Home/Pro, hardware ARM64, cambios reales de publicidad tras reinicio o escenarios de instalaci贸n/servicing en curso. Por eso la publicaci贸n se marca prerelease.

## Riesgos residuales y alcance posterior

La comprobaci贸n de rutas reduce selecciones err贸neas y redirecciones, pero no es una sandbox frente a un administrador o proceso del mismo usuario que cambie archivos entre comprobaci贸n y borrado. Usar sobre una sesi贸n controlada; ante sospecha de intrusi贸n, preservar evidencias y no limpiar.

Los toggles de publicidad son preferencias por usuario y no garantizan aplicaci贸n/persistencia en todas las builds o frente a pol铆ticas administradas. Un valor verificado significa que el registro qued贸 en el valor esperado, no prueba visual de toda publicidad eliminada.

Pendientes fuera de esta release: desinstaladores con adaptadores confiables, cat谩logo Appx exacto, endurecimiento avanzado de seguridad, cobertura de parches/soporte y adaptador opcional IOC de Zero-Breach. El diagn贸stico no es una prueba de ausencia de brechas.


## Actualizaci髇 rc.2: resumen y soluciones

El diagn髎tico interpreta estados y conserva datos crudos. Distingue riesgo de configuraci髇 de vulnerabilidad CVE confirmada. El resumen y JSON incluyen cobertura y resultados de acciones; exportan a una carpeta nueva del Escritorio obtenido con Known Folder, incluidos escritorios redirigidos o sincronizados. El detalle conserva datos privados.

Las acciones autom醫icas solo usan IDs fijos: actualizaci髇 de firmas, solicitud de an醠isis r醦ido y activaci髇 de protecci髇 en tiempo real. Reconsultan modo de Defender antes de actuar y estado despu閟. No fuerzan modo activo frente a antivirus tercero, no evitan Tamper Protection ni elevan autom醫icamente. Un an醠isis puede remediar seg鷑 Defender; la confirmaci髇 lo indica. Una solicitud no implica an醠isis completado ni equipo libre de infecci髇.

Las recomendaciones de firewall, puertos y pol韙icas siguen guiadas: no se cierran puertos ni se cambian reglas indiscriminadamente. Los estados favorables describen las se馻les observadas, no certifican el equipo. Las nuevas pruebas usan informes sint閠icos y comandos Defender simulados.
