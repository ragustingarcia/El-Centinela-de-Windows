<# : batch portion
@echo off
title El Centinela de Windows
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo.
    echo   [!] Se requieren privilegios de Administrador.
    echo   [!] Acepta el cartel de Windows que va a aparecer...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)
pushd "%CD%"
CD /D "%~dp0"
copy "%~f0" "%temp%\centinela_script.ps1" >nul
rem PowerShell 7 (pwsh) si esta instalado; si no, el Windows PowerShell 5.1
rem que trae todo Windows 10/11. El script es compatible con ambos.
where pwsh >nul 2>&1
if '%errorlevel%' EQU '0' (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%temp%\centinela_script.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%temp%\centinela_script.ps1"
)
del "%temp%\centinela_script.ps1" >nul 2>&1
exit /b
: end batch / begin PowerShell #>
# ============================================================
#   EL CENTINELA DE WINDOWS
#   Limpiador y optimizador: arranque, Defender, privacidad
#   y programas innecesarios. Re-ejecutable, no destructivo
#   por defecto (siempre pregunta antes de tocar algo).
# ============================================================

function Write-OK      { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Err     { param($msg) Write-Host "  [X] $msg" -ForegroundColor Red }
function Write-Warn    { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Info    { param($msg) Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Section { param($msg) Write-Host $msg -ForegroundColor Yellow }

function Write-Titulo { param($msg)
    Write-Host ""
    Write-Section "============================================================"
    Write-Section "  $msg"
    Write-Section "============================================================"
    Write-Host ""
}

function Ask-SN { param($pregunta)
    if ($Global:ModoSoloLectura) {
        Write-Host "  (modo reporte: no se modifica nada)" -ForegroundColor DarkGray
        return $false
    }
    $r = Read-Host "  $pregunta (s/N)"
    return ($r -match "^[sS]")
}

function Test-Sig($path) {
    if (-not $path) { return "N/A" }
    if (-not (Test-Path -LiteralPath $path)) { return "ARCHIVO NO EXISTE" }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($s.Status -eq "Valid") {
            $subject = $s.SignerCertificate.Subject
            $nombre = if ($subject -match 'CN="([^"]+)"') { $matches[1] } elseif ($subject -match 'CN=([^,]+)') { $matches[1] } else { $subject }
            return "OK ($nombre)"
        }
        else { return "SIN FIRMA VALIDA ($($s.Status))" }
    } catch { return "error de firma" }
}

# Extrae la ruta de un ejecutable de un valor de Run/servicio/tarea que puede
# venir sin comillas y con espacios en el path (ej: "C:\Program Files\X\y.exe arg").
# Prueba cada ocurrencia de ".exe" de izquierda a derecha hasta encontrar una
# que sea un archivo real - mas confiable que un regex unico.
function Extract-Path($cmd) {
    if (-not $cmd) { return $null }
    if ($cmd -match '^"([^"]+)"') { return $matches[1] }
    $idx = 0
    while (($idx = $cmd.IndexOf(".exe", $idx, [StringComparison]::OrdinalIgnoreCase)) -ge 0) {
        $candidate = $cmd.Substring(0, $idx + 4)
        if (Test-Path -LiteralPath $candidate) { return $candidate }
        $idx += 4
    }
    if ($cmd -match '^(\S+\.exe)') { return $matches[1] }
    return $cmd
}

function Get-DirSizeMB($path) {
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    $s = (Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    if (-not $s) { return 0 }
    return [math]::Round($s / 1MB, 1)
}

# Borra el CONTENIDO de una carpeta (no la carpeta en si) sin frenar ante
# archivos en uso: cada item se intenta por separado, los que fallan
# (bloqueados por otro proceso) se cuentan y se saltean sin cortar el resto.
function Remove-DirContents($path, $excluir = @()) {
    $items = Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | Where-Object { $excluir -notcontains $_.FullName }
    $ok = 0; $fail = 0
    foreach ($i in $items) {
        try { Remove-Item -LiteralPath $i.FullName -Recurse -Force -ErrorAction Stop; $ok++ }
        catch { $fail++ }
    }
    return [pscustomobject]@{ Ok = $ok; Fail = $fail }
}

# ============================================================
#  CATEGORIA 1: ARRANQUE Y PERSISTENCIA
# ============================================================
function Invoke-AuditArranque {
    Write-Titulo "ARRANQUE Y PERSISTENCIA"

    Write-Info "Revisando Run / RunOnce..."
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $hallazgos = @()
    foreach ($rk in $runKeys) {
        $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $p = Extract-Path $_.Value
                $hallazgos += [pscustomobject]@{ Key = $rk; Name = $_.Name; Value = $_.Value; Path = $p; Sig = Test-Sig $p }
            }
        }
    }
    # Estas apps manejan su PROPIO interruptor de "iniciar con Windows" y se
    # reescriben solas en el Run la proxima vez que las abras, sin importar
    # que hayas borrado la clave a mano. Border la clave es un parche
    # temporal - el arreglo real es apagarlo desde los Ajustes de la app.
    $AutoRelanzadores = [ordered]@{
        "Discord"       = "Discord > Configuracion de Usuario > Windows Settings > 'Abrir Discord automaticamente...'"
        "Docker Desktop" = "Docker Desktop > Settings (engranaje) > General > 'Start Docker Desktop when you log in'"
        "Steam"         = "Steam > Configuracion > Interfaz > 'Ejecutar Steam al iniciar Windows'"
        "Spotify"       = "Spotify > Configuracion > 'Abrir Spotify automaticamente despues de iniciar sesion'"
        "Slack"         = "Slack > Preferencias > Avanzado > 'Iniciar Slack automaticamente'"
        "Zoom"          = "Zoom > Configuracion > General > 'Iniciar Zoom cuando se inicie Windows'"
        "OneDrive"      = "OneDrive > Configuracion > 'Iniciar OneDrive automaticamente al iniciar sesion'"
    }

    if ($hallazgos.Count -eq 0) { Write-OK "Sin entradas en Run/RunOnce." }
    foreach ($h in $hallazgos) {
        Write-Host ""
        Write-Host "  [$($h.Key)]"
        Write-Host "    $($h.Name) = $($h.Value)"
        if ($h.Sig -notmatch "^OK") { Write-Warn "Firma: $($h.Sig)" } else { Write-Host "    Firma: $($h.Sig)" -ForegroundColor DarkGray }
        $hint = ($AutoRelanzadores.Keys | Where-Object { $h.Name -match [regex]::Escape($_) } | Select-Object -First 1)
        if ($hint) { Write-Info "Tip: esta app se re-agrega SOLA si la volves a abrir. Para que no vuelva: $($AutoRelanzadores[$hint])" }
        if (Ask-SN "Sacar del arranque?") {
            try { Remove-ItemProperty -Path $h.Key -Name $h.Name -ErrorAction Stop; Write-OK "Eliminado." }
            catch { Write-Err "No se pudo eliminar: $($_.Exception.Message)" }
        }
    }

    Write-Host ""
    Write-Info "Revisando carpetas de Startup..."
    $sh = New-Object -ComObject WScript.Shell
    $startupItems = @()
    foreach ($folder in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
        Get-ChildItem $folder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in ".lnk", ".exe", ".bat", ".vbs", ".js" } | ForEach-Object {
            $target = $_.FullName
            if ($_.Extension -eq ".lnk") { try { $target = $sh.CreateShortcut($_.FullName).TargetPath } catch {} }
            $startupItems += [pscustomobject]@{ File = $_.FullName; Target = $target; Sig = Test-Sig $target }
        }
    }
    if ($startupItems.Count -eq 0) { Write-OK "Carpetas de Startup vacias." }
    foreach ($it in $startupItems) {
        Write-Host ""
        Write-Host "  $($it.File)"
        Write-Host "    Apunta a: $($it.Target)"
        Write-Host "    Firma: $($it.Sig)"
        if (Ask-SN "Sacar este acceso directo del arranque?") {
            try { Remove-Item -LiteralPath $it.File -Force -ErrorAction Stop; Write-OK "Eliminado." }
            catch { Write-Err "No se pudo eliminar: $($_.Exception.Message)" }
        }
    }

    Write-Host ""
    Write-Info "Puntos de secuestro clasicos (solo diagnostico, no se tocan automaticamente)..."
    $winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($winlogon.Shell -eq "explorer.exe") { Write-OK "Winlogon Shell = explorer.exe" } else { Write-Err "Winlogon Shell = '$($winlogon.Shell)' (deberia ser explorer.exe)" }
    if ($winlogon.Userinit -match "^C:\\Windows\\system32\\userinit\.exe,?$") { Write-OK "Winlogon Userinit correcto" } else { Write-Err "Winlogon Userinit = '$($winlogon.Userinit)' (revisar)" }
    $winNT = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($winNT.AppInit_DLLs)) { Write-OK "AppInit_DLLs vacio" } else { Write-Err "AppInit_DLLs = '$($winNT.AppInit_DLLs)' (posible inyeccion de DLL)" }
    $ifeo = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue
    $hijacks = foreach ($k in $ifeo) { $d = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue; if ($d.Debugger) { "$($k.PSChildName) -> $($d.Debugger)" } }
    if ($hijacks) { Write-Err "IFEO Debugger hijacks encontrados:"; $hijacks | ForEach-Object { Write-Host "    $_" } } else { Write-OK "Sin IFEO Debugger hijacks" }
    try {
        $wmiCount = (Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop | Measure-Object).Count
        if ($wmiCount -gt 0) { Write-Warn "$wmiCount suscripcion(es) WMI activa(s) - revisar con Get-CimInstance -Namespace root/subscription -ClassName __EventFilter" } else { Write-OK "Sin suscripciones WMI" }
    } catch { Write-Info "No se pudo consultar suscripciones WMI." }

    Write-Host ""
    Write-Info "Tareas programadas no-Microsoft, habilitadas..."
    $tareas = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled" }
    if (-not $tareas) { Write-OK "Sin tareas no-Microsoft habilitadas." }
    foreach ($t in $tareas) {
        $execAction = $t.Actions | Where-Object { $_.Execute } | Select-Object -First 1
        Write-Host ""
        Write-Host "  $($t.TaskPath)$($t.TaskName)"
        if ($execAction) {
            $p = Extract-Path $execAction.Execute
            Write-Host "    Accion: $($execAction.Execute) $($execAction.Arguments)"
            Write-Host "    Firma: $(Test-Sig $p)"
        } else {
            Write-Host "    (Accion tipo COM Handler - normalmente un componente interno de Windows, no un programa instalado)"
        }
        if (Ask-SN "Deshabilitar esta tarea?") {
            try { Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null; Write-OK "Deshabilitada." }
            catch { Write-Err "No se pudo deshabilitar: $($_.Exception.Message)" }
        }
    }

    Write-Host ""
    Write-Info "Servicios de terceros con auto-inicio (diagnostico - cambialos a Manual desde services.msc si no los necesitas)..."
    $servicios = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -and $_.PathName -notmatch "\\Windows\\|\\system32\\" }
    if (-not $servicios) { Write-OK "Sin servicios de terceros con auto-inicio fuera de la carpeta de Windows." }
    foreach ($s in $servicios) {
        $p = Extract-Path $s.PathName
        Write-Host ""
        Write-Host "  $($s.Name) [$($s.State)] - $($s.DisplayName)"
        Write-Host "    Path: $($s.PathName)"
        Write-Host "    Firma: $(Test-Sig $p)"
    }
}

# ============================================================
#  CATEGORIA 2: SEGURIDAD (WINDOWS DEFENDER)
# ============================================================
function Invoke-AuditSeguridad {
    Write-Titulo "SEGURIDAD - WINDOWS DEFENDER"

    try {
        $mps = Get-MpComputerStatus -ErrorAction Stop
        Write-Host "  Proteccion en tiempo real: $(if ($mps.RealTimeProtectionEnabled) { 'ACTIVA' } else { 'INACTIVA' })"
        Write-Host "  Antivirus activo: $($mps.AntivirusEnabled)"
        Write-Host "  Ultimo scan rapido: $($mps.QuickScanEndTime)"
        Write-Host "  Ultimo scan completo: $($mps.FullScanEndTime)"
        Write-Host "  Definiciones: $($mps.AntivirusSignatureVersion) ($($mps.AntivirusSignatureLastUpdated))"
    } catch { Write-Warn "No se pudo leer el estado de Defender: $($_.Exception.Message)" }

    Write-Host ""
    Write-Info "Exclusiones configuradas..."
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        # Get-MpPreference sin admin NO tira excepcion: devuelve el string literal
        # "N/A: Must be an administrator to view exclusions" como si fuera un valor
        # real. Hay que filtrarlo explicitamente o el script lo confunde con datos.
        $esPlaceholder = { param($v) $v -match "^N/A: Must be an administrator" }
        if ((@($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)) | Where-Object { & $esPlaceholder $_ }) {
            Write-Warn "No se pudieron leer las exclusiones (requiere admin). Si estas corriendo el .bat normalmente ya deberias tener permisos - revisa que la ventana haya aceptado el cartel de UAC."
        } else {
            $rutas = @($mp.ExclusionPath | Where-Object { $_ })
            $huerfanas = @($rutas | Where-Object { -not (Test-Path -LiteralPath $_) })
            $vivas = @($rutas | Where-Object { Test-Path -LiteralPath $_ })
            if ($huerfanas.Count -gt 0) {
                Write-Warn "$($huerfanas.Count) ruta(s) excluida(s) que YA NO EXISTEN en disco (no hacen nada, solo ensucian la config):"
                $huerfanas | ForEach-Object { Write-Host "    $_" }
                if (Ask-SN "Limpiar estas exclusiones huerfanas?") {
                    Remove-MpPreference -ExclusionPath $huerfanas
                    Write-OK "Limpiadas."
                }
            } else { Write-OK "Sin exclusiones huerfanas." }
            if ($vivas.Count -gt 0) {
                Write-Info "Rutas excluidas que SI existen (revisar si las reconoces, no se tocan automaticamente):"
                $vivas | ForEach-Object { Write-Host "    $_" }
            }
            if ($mp.ExclusionProcess) { Write-Warn "Procesos excluidos (revisar - la categoria mas sensible):"; $mp.ExclusionProcess | ForEach-Object { Write-Host "    $_" } } else { Write-OK "Sin procesos excluidos." }
            if ($mp.ExclusionExtension) { Write-Warn "Extensiones excluidas (revisar):"; $mp.ExclusionExtension | ForEach-Object { Write-Host "    $_" } } else { Write-OK "Sin extensiones excluidas." }
        }
    } catch { Write-Warn "No se pudieron leer las exclusiones: $($_.Exception.Message)" }

    if (-not $Global:ModoSoloLectura) {
        Write-Host ""
        Write-Host "  Correr un scan de Defender ahora?"
        Write-Host "    [1] Rapido"
        Write-Host "    [2] Completo (puede tardar mas de una hora)"
        Write-Host "    [3] No, gracias"
        $op = Read-Host "  Elegi una opcion"
        switch ($op) {
            "1" { Write-Info "Iniciando scan rapido..."; Start-MpScan -ScanType QuickScan; Write-OK "Listo." }
            "2" { Write-Info "Iniciando scan completo (esto corre en primer plano)..."; Start-MpScan -ScanType FullScan; Write-OK "Listo." }
            default { Write-Info "Sin scan." }
        }
    }
}

# ============================================================
#  CATEGORIA 3: PRIVACIDAD (SUGERENCIAS / PUBLICIDAD DE WINDOWS)
# ============================================================
function Invoke-AuditPrivacidad {
    Write-Titulo "PRIVACIDAD - SUGERENCIAS Y PUBLICIDAD DE WINDOWS"
    # $env:USERNAME puede venir HEREDADO del proceso padre y no reflejar la
    # identidad real del token elevado - se usa la API de Windows en vez de
    # confiar en la variable de entorno.
    $identidad = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Info "Identidad real del proceso: $($identidad.Name) (variable de entorno: $env:USERDOMAIN\$env:USERNAME)"
    Write-Info "Perfil: $env:USERPROFILE"
    Write-Info "SID: $($identidad.User.Value)"

    $cdm = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    $keys = @(
        "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-353698Enabled",
        "SystemPaneSuggestionsEnabled", "SilentInstalledAppsEnabled", "PreInstalledAppsEnabled",
        "OemPreInstalledAppsEnabled", "RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled", "SoftLandingEnabled"
    )
    $actuales = Get-ItemProperty $cdm -ErrorAction SilentlyContinue
    $activos = 0
    foreach ($k in $keys) {
        $v = $actuales.$k
        if ($null -eq $v -or $v -eq 1) { $activos++; Write-Warn "$k = ACTIVO" } else { Write-Host "    $k = apagado" -ForegroundColor DarkGray }
    }

    # Estos toggles por-usuario son "blandos": Windows los puede resetear solo
    # con el tiempo, tras una actualizacion, o si la cuenta que eleva el .bat
    # no es la misma que los seteo. Las 4 politicas de HKLM de abajo son la
    # version "pegajosa" (Group Policy) que Windows respeta como anulacion
    # dura y aplica a TODOS los usuarios de la maquina, no a uno solo.
    $gpo = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $gpoKeys = [ordered]@{
        "DisableWindowsConsumerFeatures"                = "Apps preinstaladas/instaladas en silencio"
        "DisableSoftLanding"                             = "Motor SoftLanding (recomendaciones/tips)"
        "DisableThirdPartySuggestions"                   = "Sugerencias de apps de terceros"
        "DisableTailoredExperiencesWithDiagnosticData"   = "Contenido personalizado segun tus datos de diagnostico"
    }
    $gpoActuales = Get-ItemProperty $gpo -ErrorAction SilentlyContinue
    $gpoFaltantes = @($gpoKeys.Keys | Where-Object { $gpoActuales.$_ -ne 1 })

    Write-Host ""
    if ($activos -eq 0 -and $gpoFaltantes.Count -eq 0) { Write-OK "Todo apagado, incluidas las politicas persistentes."; return }
    if ($activos -gt 0) {
        Write-Info "$activos de $($keys.Count) sugerencias/publicidad (config por-usuario) estan activas."
    }
    if ($gpoFaltantes.Count -gt 0) {
        Write-Warn "$($gpoFaltantes.Count) de $($gpoKeys.Count) politicas persistentes NO estan activas - por esto Windows puede haber revertido una limpieza anterior."
    } else {
        Write-OK "Las 4 politicas persistentes ya estan activas."
    }
    Write-Host "  Incluye: recomendaciones del menu Inicio, apps instaladas en silencio,"
    Write-Host "  apps preinstaladas de OEM, y pantalla de bloqueo rotativa con overlay de tips."
    if ($Global:ModoSoloLectura) { return }
    Write-Host ""
    Write-Host "  [1] Apagar todo (recomendado - incluye las politicas persistentes)"
    Write-Host "  [2] Apagar sugerencias/apps, mantener las fotos de Spotlight (sin overlay de tips)"
    Write-Host "  [3] No tocar nada"
    $op = Read-Host "  Elegi una opcion"
    $toApply = @{}
    switch ($op) {
        "1" { foreach ($k in $keys) { $toApply[$k] = 0 } }
        "2" { foreach ($k in $keys) { $toApply[$k] = 0 }; $toApply["RotatingLockScreenEnabled"] = 1 }
        default { Write-Info "Sin cambios."; return }
    }
    foreach ($k in $toApply.Keys) { New-ItemProperty -Path $cdm -Name $k -Value $toApply[$k] -PropertyType DWord -Force | Out-Null }
    if (-not (Test-Path $gpo)) { New-Item -Path $gpo -Force | Out-Null }
    foreach ($k in $gpoKeys.Keys) { New-ItemProperty -Path $gpo -Name $k -Value 1 -PropertyType DWord -Force | Out-Null }
    Write-OK "Aplicado (config por-usuario + politicas persistentes). Puede requerir cerrar sesion para verse reflejado."
}

# ============================================================
#  CATEGORIA 4: PROGRAMAS CONOCIDOS COMO INNECESARIOS
# ============================================================
# Confianza "Verificado" = probado en una maquina real durante esta sesion de limpieza.
# Confianza "Publico" = documentado por la comunidad tecnica, NO probado en esta sesion.
# Revisar=$true = tiene utilidad real para algunos; la pregunta se formula distinto.
$BloatwareDB = @(
    [pscustomobject]@{ Nombre = "Intel Computing Improvement Program"; Vendor = "Intel"; Confianza = "Verificado"; Tipo = "uninstall"; Patron = "Computing Improvement Program"; Desc = "Telemetria de uso de Intel, sin beneficio para el usuario."; Revisar = $false }
    [pscustomobject]@{ Nombre = "Intel System Usage Report (QUEENCREEK)"; Vendor = "Intel"; Confianza = "Verificado"; Tipo = "service"; Patron = "QUEENCREEK"; Desc = "Servicios de telemetria de Intel en segundo plano."; Revisar = $false }
    [pscustomobject]@{ Nombre = "AMD Dual-Core Optimizer"; Vendor = "AMD"; Confianza = "Verificado"; Tipo = "uninstall"; Patron = "Dual-Core Optimizer"; Desc = "Parche para CPUs AMD de ~2005-2008. Inutil en cualquier PC moderna sea cual sea la marca de CPU; suele colarse con instaladores de juegos viejos."; Revisar = $false }
    [pscustomobject]@{ Nombre = "NVIDIA FrameView SDK"; Vendor = "NVIDIA"; Confianza = "Verificado"; Tipo = "uninstall"; Patron = "FrameView"; Desc = "Modulo de benchmark/telemetria de la NVIDIA App. No afecta drivers ni juegos."; Revisar = $false }

    [pscustomobject]@{ Nombre = "Dell Digital Delivery"; Vendor = "Dell"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "Dell Digital Delivery"; Desc = "Entrega de software promocional preinstalado por Dell. Sin funcion tecnica."; Revisar = $false }
    [pscustomobject]@{ Nombre = "Dell Customer Connect"; Vendor = "Dell"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "Dell Customer Connect"; Desc = "Marketing y encuestas de Dell."; Revisar = $false }
    [pscustomobject]@{ Nombre = "HP JumpStart"; Vendor = "HP"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "HP JumpStart"; Desc = "Suite promocional de HP, ampliamente documentada como bloatware de venta cruzada."; Revisar = $false }
    [pscustomobject]@{ Nombre = "WildTangent Games / Helper"; Vendor = "WildTangent"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "WildTangent"; Desc = "Plataforma de juegos casuales con publicidad, preinstalada en muchos OEMs (Dell/HP/Acer)."; Revisar = $false }
    [pscustomobject]@{ Nombre = "McAfee (trial preinstalado)"; Vendor = "McAfee"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "^McAfee"; Desc = "Es un ANTIVIRUS REAL de prueba, no telemetria pura."; Revisar = $true }
    [pscustomobject]@{ Nombre = "Norton (trial preinstalado)"; Vendor = "Norton / Gen Digital"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "Norton (Security|360|AntiVirus)"; Desc = "Mismo caso que McAfee: antivirus real de prueba."; Revisar = $true }
    [pscustomobject]@{ Nombre = "MyASUS / Armoury Crate"; Vendor = "ASUS"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "^MyASUS$|Armoury Crate"; Desc = "Tiene funciones reales (BIOS, RGB, perifericos) ademas de contenido promocional."; Revisar = $true }
    [pscustomobject]@{ Nombre = "HP Support Assistant"; Vendor = "HP"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "HP Support Assistant"; Desc = "Actualiza drivers de HP pero tambien empuja ofertas. Utilidad real, es gusto personal."; Revisar = $true }
    [pscustomobject]@{ Nombre = "Dell SupportAssist"; Vendor = "Dell"; Confianza = "Publico"; Tipo = "uninstall"; Patron = "Dell SupportAssist"; Desc = "Diagnostico y drivers de Dell. Tuvo vulnerabilidades documentadas en el pasado - si lo conservas, mantenelo actualizado."; Revisar = $true }
)

function Remove-BloatEntry($entry) {
    $uninstStr = if ($entry.QuietUninstallString) { $entry.QuietUninstallString } else { $entry.UninstallString }
    if (-not $uninstStr) { Write-Err "Sin comando de desinstalacion registrado, no se puede sacar automaticamente."; return }
    if ($uninstStr -match "msiexec.*?(\{[0-9A-Fa-f\-]+\})") {
        Start-Process msiexec -ArgumentList "/X", $matches[1], "/qn", "/norestart" -Wait
    } elseif ($entry.QuietUninstallString) {
        Start-Process cmd -ArgumentList "/c", $entry.QuietUninstallString -Wait
    } else {
        Write-Info "Se abre el desinstalador oficial - completalo en la ventana que aparece (no adivinamos flags silenciosos de terceros)."
        Start-Process cmd -ArgumentList "/c", $uninstStr -Wait
    }
}

function Invoke-AuditBloatware {
    Write-Titulo "PROGRAMAS CONOCIDOS COMO INNECESARIOS"
    Write-Host "  [Verificado] = probado de verdad en una maquina real."
    Write-Host "  [Publico]    = documentado por la comunidad, NO probado en esta sesion - confirmalo antes de sacarlo."
    $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $todos = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue
    $encontrados = 0
    foreach ($item in $BloatwareDB) {
        if ($item.Tipo -eq "uninstall") {
            $match = $todos | Where-Object { $_.DisplayName -match $item.Patron }
            if (-not $match) { continue }
            $encontrados++
            Write-Host ""
            Write-Host "  [$($item.Confianza)] $($item.Nombre) ($($item.Vendor))"
            Write-Host "    $($item.Desc)"
            foreach ($m in $match) {
                Write-Host "    Encontrado: $($m.DisplayName) $($m.DisplayVersion)"
                $pregunta = if ($item.Revisar) { "Si NO usas esto, sacarlo ahora?" } else { "Sacarlo ahora?" }
                if (Ask-SN $pregunta) { Remove-BloatEntry $m; Write-OK "Desinstalacion iniciada/completada." }
            }
        } elseif ($item.Tipo -eq "service") {
            $svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $item.Patron -or $_.DisplayName -match $item.Patron }
            if (-not $svc) { continue }
            $encontrados++
            Write-Host ""
            Write-Host "  [$($item.Confianza)] $($item.Nombre) ($($item.Vendor))"
            Write-Host "    $($item.Desc)"
            foreach ($s in $svc) {
                Write-Host "    Servicio: $($s.Name) [$($s.State)]"
                if (Ask-SN "Detener y eliminar este servicio?") {
                    if ($s.State -eq "Running") { Stop-Service $s.Name -Force -ErrorAction SilentlyContinue }
                    sc.exe delete $s.Name | Out-Null
                    Write-OK "Servicio eliminado."
                }
            }
        }
    }
    if ($encontrados -eq 0) { Write-OK "No se encontro ninguno de los $($BloatwareDB.Count) programas de la lista conocida." }
}

# ============================================================
#  CATEGORIA 5: LIMPIEZA DE DISCO
# ============================================================
function Invoke-LimpiezaDisco {
    Write-Titulo "LIMPIEZA DE DISCO"
    # El propio script vive como copia temporal en $env:TEMP mientras corre -
    # se excluye explicitamente para no auto-borrarse a mitad de ejecucion.
    $miScript = $PSCommandPath

    $antes = (Get-PSDrive C -ErrorAction SilentlyContinue).Free
    if ($antes) { Write-Info "Espacio libre actual en C: $([math]::Round($antes/1GB,1)) GB" }

    Write-Host ""
    Write-Info "Calculando temporales de Windows..."
    $tempUser = $env:TEMP
    $tempSys = "C:\Windows\Temp"
    $mbUser = Get-DirSizeMB $tempUser
    $mbSys = Get-DirSizeMB $tempSys
    Write-Host "  Temp de usuario ($tempUser): $mbUser MB"
    Write-Host "  Temp del sistema ($tempSys): $mbSys MB"
    if (($mbUser + $mbSys) -gt 0) {
        if (Ask-SN "Borrar estos temporales? (los archivos en uso se saltean solos, sin riesgo)") {
            $r1 = Remove-DirContents $tempUser @($miScript)
            $r2 = Remove-DirContents $tempSys
            Write-OK "Temp de usuario: $($r1.Ok) borrados, $($r1.Fail) en uso (salteados)."
            Write-OK "Temp del sistema: $($r2.Ok) borrados, $($r2.Fail) en uso (salteados)."
        }
    } else { Write-OK "Temporales ya estan vacios." }

    Write-Host ""
    Write-Info "Calculando cache de navegadores (Chrome/Edge, todos los perfiles)..."
    $navegadores = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    )
    $totalCacheMB = 0
    $cachePaths = @()
    foreach ($base in $navegadores) {
        if (-not (Test-Path $base)) { continue }
        Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($sub in @("Cache", "Code Cache", "GPUCache")) {
                $p = Join-Path $_.FullName $sub
                $mb = Get-DirSizeMB $p
                if ($mb -gt 0) { $totalCacheMB += $mb; $cachePaths += $p }
            }
        }
    }
    Write-Host "  Total cache: $([math]::Round($totalCacheMB,1)) MB en $($cachePaths.Count) carpetas"
    if ($totalCacheMB -gt 0) {
        Write-Info "Tip: cerra el navegador antes de esto para que no se recree mientras se borra."
        if (Ask-SN "Borrar la cache de los navegadores?") {
            $ok = 0; $fail = 0
            foreach ($p in $cachePaths) { $r = Remove-DirContents $p; $ok += $r.Ok; $fail += $r.Fail }
            Write-OK "$ok archivos borrados, $fail en uso (salteados - normal si el navegador esta abierto)."
        }
    } else { Write-OK "Sin cache significativa." }

    Write-Host ""
    Write-Info "Papelera de reciclaje..."
    try {
        $shellCom = New-Object -ComObject Shell.Application
        $bin = $shellCom.Namespace(0xA)
        $items = @($bin.Items())
        if ($items.Count -gt 0) {
            $mbPapelera = [math]::Round((($items | ForEach-Object { $_.Size } | Measure-Object -Sum).Sum) / 1MB, 1)
            Write-Host "  $($items.Count) elemento(s), $mbPapelera MB"
            if (Ask-SN "Vaciar la Papelera de reciclaje? (PERMANENTE, no se puede deshacer)") {
                $borrados = 0
                foreach ($item in $items) {
                    try { Remove-Item -LiteralPath $item.Path -Recurse -Force -ErrorAction Stop; $borrados++ } catch {}
                }
                Write-OK "$borrados de $($items.Count) elemento(s) borrados."
            }
        } else { Write-OK "Papelera ya vacia." }
    } catch { Write-Warn "No se pudo acceder a la Papelera: $($_.Exception.Message)" }

    Write-Host ""
    Write-Info "Descargas acumuladas de Windows Update..."
    $wuPath = "C:\Windows\SoftwareDistribution\Download"
    $mbWU = Get-DirSizeMB $wuPath
    Write-Host "  $wuPath : $mbWU MB"
    if ($mbWU -gt 50) {
        if (Ask-SN "Limpiar? (Windows vuelve a descargar lo que necesite despues, no rompe nada)") {
            try {
                Write-Info "Deteniendo el servicio de Windows Update..."
                Stop-Service wuauserv -Force -ErrorAction Stop
                $r = Remove-DirContents $wuPath
                Start-Service wuauserv
                Write-OK "$($r.Ok) elemento(s) borrados, servicio de Windows Update reiniciado."
            } catch {
                Write-Err "No se pudo limpiar: $($_.Exception.Message)"
                Start-Service wuauserv -ErrorAction SilentlyContinue
            }
        }
    } else { Write-OK "Poco o nada acumulado ($mbWU MB)." }

    Write-Host ""
    Write-Info "Cache de Delivery Optimization (piezas de actualizaciones compartidas entre PCs)..."
    try {
        Get-DeliveryOptimizationStatus -ErrorAction Stop | Out-Null
        if (Ask-SN "Limpiar la cache de Delivery Optimization?") {
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop *>$null
            Write-OK "Limpiada."
        }
    } catch { Write-Info "No disponible en este Windows (no es un problema)." }

    Write-Host ""
    if (Test-Path "C:\Windows.old") {
        $mbOld = Get-DirSizeMB "C:\Windows.old"
        Write-Warn "Existe C:\Windows.old ($mbOld MB) - restos de una actualizacion de Windows anterior."
        Write-Info "No se borra automaticamente aca (tiene permisos especiales que lo hacen delicado). Para sacarlo: Configuracion > Almacenamiento > Archivos temporales > 'Instalacion anterior de Windows'."
    } else { Write-OK "Sin C:\Windows.old" }

    Write-Host ""
    $despues = (Get-PSDrive C -ErrorAction SilentlyContinue).Free
    if ($antes -and $despues) {
        $liberadoGB = [math]::Round(($despues - $antes) / 1GB, 2)
        if ($liberadoGB -gt 0) { Write-OK "Espacio liberado en esta pasada: $liberadoGB GB" }
        Write-Info "Espacio libre ahora en C: $([math]::Round($despues/1GB,1)) GB"
    }
}

# ============================================================
#  CATEGORIA 7: APPS DE LA TIENDA PREINSTALADAS
# ============================================================
# LISTA BLANCA ESTRICTA: solo se ofrece sacar lo que esta explicitamente
# ACA. Nunca se toca nada fuera de esta lista - muchos paquetes Appx son
# piezas del propio Windows (Start, Explorer, Widgets, teclado tactil,
# Xbox Game Bar/overlay) y sacar el equivocado puede romper el sistema.
# Por eso NO hay un enfoque de "blocklist" (sacar todo menos lo protegido).
$AppsTiendaDB = @(
    [pscustomobject]@{ Patron = "*CandyCrush*";                   Nombre = "Candy Crush (todas las variantes)";              Revisar = $false }
    [pscustomobject]@{ Patron = "king.com.*";                     Nombre = "Otros juegos de King.com";                        Revisar = $false }
    [pscustomobject]@{ Patron = "*BubbleWitch*";                  Nombre = "Bubble Witch Saga";                               Revisar = $false }
    [pscustomobject]@{ Patron = "*Disney*";                       Nombre = "Disney+";                                         Revisar = $false }
    [pscustomobject]@{ Patron = "*Netflix*";                      Nombre = "Netflix";                                         Revisar = $false }
    [pscustomobject]@{ Patron = "*SpotifyAB.SpotifyMusic*";       Nombre = "Spotify (version Tienda)";                        Revisar = $true }
    [pscustomobject]@{ Patron = "*TikTok*";                       Nombre = "TikTok";                                          Revisar = $false }
    [pscustomobject]@{ Patron = "*Instagram*";                    Nombre = "Instagram";                                       Revisar = $false }
    [pscustomobject]@{ Patron = "*Facebook*";                     Nombre = "Facebook";                                        Revisar = $false }
    [pscustomobject]@{ Patron = "*Twitter*";                      Nombre = "Twitter / X";                                     Revisar = $false }
    [pscustomobject]@{ Patron = "*LinkedIn*";                     Nombre = "LinkedIn";                                        Revisar = $false }
    [pscustomobject]@{ Patron = "*MicrosoftSolitaireCollection*"; Nombre = "Solitario de Microsoft (con publicidad)";         Revisar = $true }
    [pscustomobject]@{ Patron = "*BingNews*";                     Nombre = "Noticias (MSN/Bing News)";                        Revisar = $false }
    [pscustomobject]@{ Patron = "*BingWeather*";                  Nombre = "Clima (MSN/Bing Weather)";                        Revisar = $true }
    [pscustomobject]@{ Patron = "*BingFinance*";                  Nombre = "Finanzas (MSN Money)";                            Revisar = $false }
    [pscustomobject]@{ Patron = "*MixedReality*";                 Nombre = "Mixed Reality Portal (si no tenes visor VR)";     Revisar = $true }
    [pscustomobject]@{ Patron = "*Microsoft3DViewer*";            Nombre = "Visor 3D";                                        Revisar = $false }
    [pscustomobject]@{ Patron = "*MSPaint*";                      Nombre = "Paint 3D (discontinuado por Microsoft)";          Revisar = $false }
    [pscustomobject]@{ Patron = "*ZuneMusic*";                    Nombre = "Groove Music (discontinuado)";                    Revisar = $false }
    [pscustomobject]@{ Patron = "*ZuneVideo*";                    Nombre = "Peliculas y TV";                                  Revisar = $true }
    [pscustomobject]@{ Patron = "*GetHelp*";                      Nombre = "Obtener ayuda";                                   Revisar = $true }
    [pscustomobject]@{ Patron = "*Getstarted*";                   Nombre = "Sugerencias/introduccion a Windows";              Revisar = $false }
    [pscustomobject]@{ Patron = "*WindowsFeedbackHub*";           Nombre = "Hub de comentarios";                              Revisar = $true }
    [pscustomobject]@{ Patron = "*YourPhone*";                    Nombre = "Vinculo con tu telefono (Phone Link)";            Revisar = $true }
    [pscustomobject]@{ Patron = "*.Todos*";                       Nombre = "Microsoft To Do";                                 Revisar = $true }
    [pscustomobject]@{ Patron = "*Microsoft.GamingApp*";          Nombre = "App de Xbox (companion de consola)";              Revisar = $true }
    [pscustomobject]@{ Patron = "*Microsoft.XboxApp*";            Nombre = "App de Xbox (version vieja)";                     Revisar = $true }
    [pscustomobject]@{ Patron = "*Clipchamp*";                    Nombre = "Clipchamp (editor de video, con version paga)";   Revisar = $true }
    [pscustomobject]@{ Patron = "*MicrosoftTeams*";               Nombre = "Teams (chat personal/consumer, no el de trabajo)"; Revisar = $true }
)

function Invoke-AuditAppsTienda {
    Write-Titulo "APPS DE LA TIENDA PREINSTALADAS"
    Write-Host "  Solo se ofrece sacar apps de esta lista curada - nunca se toca nada"
    Write-Host "  fuera de ella (muchos paquetes son del propio Windows y sacarlos puede romper el sistema)."
    Write-Host "  [Revisar] = tiene uso real para algunos - confirma que no lo usas antes de sacarlo."
    Write-Host ""

    $instaladas = Get-AppxPackage -ErrorAction SilentlyContinue
    $encontradas = 0
    foreach ($item in $AppsTiendaDB) {
        $match = @($instaladas | Where-Object { $_.Name -like $item.Patron -or $_.PackageFullName -like $item.Patron })
        if ($match.Count -eq 0) { continue }
        $encontradas++
        Write-Host ""
        $tag = if ($item.Revisar) { "[Revisar]" } else { "[Bloatware]" }
        Write-Host "  $tag $($item.Nombre)"
        foreach ($m in $match) {
            Write-Host "    $($m.Name) (version $($m.Version))"
            $pregunta = if ($item.Revisar) { "Si NO usas esto, sacarlo ahora?" } else { "Sacarlo ahora?" }
            if (Ask-SN $pregunta) {
                try {
                    Remove-AppxPackage -Package $m.PackageFullName -ErrorAction Stop
                    Write-OK "Eliminada de tu cuenta."
                    $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $m.Name }
                    if ($prov) {
                        if (Ask-SN "  Tambien evitar que se reinstale para OTRAS cuentas nuevas de esta PC?") {
                            try { Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null; Write-OK "  Tambien deprovisionada." }
                            catch { Write-Err "  No se pudo deprovisionar: $($_.Exception.Message)" }
                        }
                    }
                } catch { Write-Err "No se pudo eliminar: $($_.Exception.Message)" }
            }
        }
    }
    if ($encontradas -eq 0) { Write-OK "No se encontro ninguna de las $($AppsTiendaDB.Count) apps de la lista." }
}

# ============================================================
#  REPORTE COMPLETO (envuelve las 6 categorias en modo solo-lectura)
# ============================================================
function Invoke-ReporteCompleto {
    Write-Titulo "REPORTE COMPLETO - SOLO DIAGNOSTICO, NO SE MODIFICA NADA"
    $Global:ModoSoloLectura = $true
    try {
        Invoke-AuditArranque
        Invoke-AuditSeguridad
        Invoke-AuditPrivacidad
        Invoke-AuditBloatware
        Invoke-LimpiezaDisco
        Invoke-AuditAppsTienda
    } finally {
        $Global:ModoSoloLectura = $false
    }
    Write-Titulo "FIN DEL REPORTE - entra a una categoria especifica del menu si queres actuar sobre algo"
}

# ============================================================
#  MENU PRINCIPAL
# ============================================================
$Global:ModoSoloLectura = $false
Write-Host ""
Write-Section "  ================================================="
Write-Section "     EL CENTINELA DE WINDOWS"
Write-Section "     Limpiador y optimizador"
Write-Host "     Por Rodolfo Agustin Garcia - ragustingarcia.com" -ForegroundColor DarkGray
Write-Section "  ================================================="

while ($true) {
    Write-Host ""
    Write-Host "  [1] Reporte completo (diagnostico, no modifica nada)"
    Write-Host "  [2] Arranque y persistencia"
    Write-Host "  [3] Seguridad (Windows Defender)"
    Write-Host "  [4] Privacidad (sugerencias/publicidad de Windows)"
    Write-Host "  [5] Programas conocidos como innecesarios"
    Write-Host "  [6] Limpieza de disco"
    Write-Host "  [7] Apps de la Tienda preinstaladas"
    Write-Host "  [0] Salir"
    Write-Host ""
    $choice = Read-Host "  Elegi una opcion"
    switch ($choice) {
        "1" { Invoke-ReporteCompleto }
        "2" { Invoke-AuditArranque }
        "3" { Invoke-AuditSeguridad }
        "4" { Invoke-AuditPrivacidad }
        "5" { Invoke-AuditBloatware }
        "6" { Invoke-LimpiezaDisco }
        "7" { Invoke-AuditAppsTienda }
        "0" { Write-Host ""; Write-OK "Listo, hasta la proxima."; Start-Sleep 1; exit }
        default { Write-Warn "Opcion invalida." }
    }
    if ($choice -ne "0") {
        Write-Host ""
        Read-Host "  Presiona ENTER para volver al menu"
    }
}
