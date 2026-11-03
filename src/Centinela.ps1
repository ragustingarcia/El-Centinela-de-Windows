param([switch]$LibraryOnly, [switch]$Audit, [string]$ReportPath)
$ErrorActionPreference = 'Stop'
$script:Version = '0.3.0-rc.1'
$script:PrivacyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$script:PrivacyNames = @('SubscribedContent-338388Enabled','SubscribedContent-338389Enabled','SubscribedContent-353698Enabled','SystemPaneSuggestionsEnabled','SilentInstalledAppsEnabled','PreInstalledAppsEnabled','OemPreInstalledAppsEnabled','RotatingLockScreenOverlayEnabled','SoftLandingEnabled')
function Confirm-Choice($Question) {
    $answer = Read-Host "$Question (s/N)"
    return ($null -ne $answer -and $answer.Trim() -match '^(?i:s|si|sí)$')
}
function Get-Identity {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}
function Test-LocalPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path -match '^[^:]+::') { throw 'Ruta no local o no absoluta.' }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -ne $Path.TrimEnd('\')) { throw 'Ruta no canonica.' }
    $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Se requiere una unidad local fija.' }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Ruta redirigida: $current" }
        }
        $parent = Split-Path -Path $current -Parent
        if ($parent -eq $current) { break }; $current = $parent
    }
    return $full
}
function Get-StateFolder {
    $base = [Environment]::GetFolderPath('LocalApplicationData')
    $folder = Join-Path $base 'Centinela\State'
    Test-LocalPath $folder | Out-Null
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    Test-LocalPath $folder | Out-Null
    Protect-StateFolder $folder
    return $folder
}
function Protect-StateFolder([string]$folder) {
    Test-LocalPath $folder | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @((Get-Identity),'S-1-5-18')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule ((New-Object Security.Principal.SecurityIdentifier $sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $folder -AclObject $acl
}
function Save-Journal($Journal,[string]$Path) {
    Test-LocalPath $Path | Out-Null
    $tmp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $Journal | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }
}
function Read-PrivacyValue($Name) {
    if ($script:PrivacyNames -notcontains $Name) { throw 'Ajuste desconocido.' }
    if (-not (Test-Path -LiteralPath $script:PrivacyPath)) { return $null }
    $key = Get-Item -LiteralPath $script:PrivacyPath
    if ($key.GetValueNames() -notcontains $Name) { return $null }
    if ($key.GetValueKind($Name) -ne 'DWord') { throw "Tipo no soportado: $Name" }
    return [int]$key.GetValue($Name)
}
function Write-PrivacyValue($Name,$Value) {
    if ($script:PrivacyNames -notcontains $Name) { throw 'Ajuste desconocido.' }
    if ($null -eq $Value) {
        if (Test-Path -LiteralPath $script:PrivacyPath) { Remove-ItemProperty -LiteralPath $script:PrivacyPath -Name $Name -ErrorAction Stop }
    } else {
        if ($Value -isnot [int] -and $Value -isnot [long]) { throw 'Valor no entero.' }
        if (-not (Test-Path -LiteralPath $script:PrivacyPath)) { New-Item -Path $script:PrivacyPath -Force | Out-Null }
        New-ItemProperty -LiteralPath $script:PrivacyPath -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
}
function New-PrivacyPlan {
    foreach ($name in $script:PrivacyNames) {
        try {
            $old = Read-PrivacyValue $name
            if ($null -eq $old -or $old -ne 0) { [pscustomobject]@{ Name=$name; Before=$old; After=0; Status='Pending' } }
        } catch { Write-Warning $_.Exception.Message }
    }
}
function Invoke-PrivacyPlan($Plan,[string]$JournalPath) {
    $journal = [pscustomobject]@{ Schema=1; Version=$script:Version; Sid=(Get-Identity); Machine=$env:COMPUTERNAME; Created=[DateTime]::UtcNow.ToString('o'); Entries=@($Plan) }
    foreach ($entry in $journal.Entries) {
        if ($script:PrivacyNames -notcontains $entry.Name -or $entry.After -ne 0) { throw 'Plan no permitido.' }
    }
    Save-Journal $journal $JournalPath # A failed backup prevents all writes.
    foreach ($entry in $journal.Entries) {
        try {
            $current = Read-PrivacyValue $entry.Name
            if ($current -ne $entry.Before -or (($null -eq $current) -ne ($null -eq $entry.Before))) { throw 'Estado cambiado desde la vista previa.' }
            $entry.Status='Started'; Save-Journal $journal $JournalPath
            Write-PrivacyValue $entry.Name ([int]0)
            if ((Read-PrivacyValue $entry.Name) -ne 0) { throw 'El valor no cambio.' }
            $entry.Status='Verified'
        } catch { $entry.Status='Failed'; Write-Warning ($entry.Name+': '+$_.Exception.Message) }
        Save-Journal $journal $JournalPath
    }
    return $journal
}
function Undo-Privacy([string]$JournalPath) {
    Test-LocalPath $JournalPath | Out-Null
    if ((Get-Item -LiteralPath $JournalPath).Length -gt 1MB) { throw 'Registro demasiado grande.' }
    $journal = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
    if ($journal.Schema -ne 1 -or $journal.Sid -ne (Get-Identity) -or $journal.Machine -ne $env:COMPUTERNAME -or @($journal.Entries).Count -gt $script:PrivacyNames.Count) { throw 'Registro incompatible con esta identidad o maquina.' }
    foreach ($e in $journal.Entries) {
        if ($script:PrivacyNames -notcontains $e.Name -or $e.After -ne 0 -or ($null -ne $e.Before -and ($e.Before -isnot [int] -and $e.Before -isnot [long]))) { throw 'Registro invalido.' }
    }
    foreach ($e in $journal.Entries) {
        if ($e.Status -eq 'Restored' -or $e.Status -eq 'Pending') { continue }
        try {
            if ((Read-PrivacyValue $e.Name) -ne 0) { throw 'Cambio posterior detectado; se conserva.' }
            Write-PrivacyValue $e.Name $e.Before
            $actual = Read-PrivacyValue $e.Name
            if ($actual -ne $e.Before -or (($null -eq $actual) -ne ($null -eq $e.Before))) { throw 'Restauracion no verificada.' }
            $e.Status='Restored'
        } catch { Write-Warning ($e.Name+': '+$_.Exception.Message) }
        Save-Journal $journal $JournalPath
    }
    return $journal
}
function Get-TempRoot {
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp'
}
function Get-TempPlan([int]$Days=14) {
    if ($Days -lt 14) { throw 'Antiguedad minima: 14 dias.' }
    $root = Test-LocalPath (Get-TempRoot)
    if (-not (Test-Path -LiteralPath $root)) { return }
    $cutoff = [DateTime]::UtcNow.AddDays(-$Days)
    $stack = New-Object 'Collections.Generic.Stack[string]'; $stack.Push($root)
    $count=0
    while ($stack.Count) {
        $dir=$stack.Pop(); Test-LocalPath $dir | Out-Null
        foreach ($item in Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) {
            $count++; if ($count -gt 10000) { throw 'Limite de 10000 elementos alcanzado; limpieza cancelada. Seleccionar una carpeta menor desde Almacenamiento.' }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($item.PSIsContainer) { $stack.Push($item.FullName); continue }
            if ($item.LastWriteTimeUtc -lt $cutoff -and $item.CreationTimeUtc -lt $cutoff) {
                [pscustomobject]@{ Path=$item.FullName; Length=$item.Length; Modified=$item.LastWriteTimeUtc.Ticks; Created=$item.CreationTimeUtc.Ticks }
            }
        }
    }
}
function Invoke-TempPlan($Plan) {
    $root=Test-LocalPath (Get-TempRoot); $bytes=[long]0; $deleted=0; $skipped=0
    foreach ($entry in $Plan) {
        try {
            $path=Test-LocalPath $entry.Path
            if (-not $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Fuera del destino permitido.' }
            $item=Get-Item -LiteralPath $path -Force
            if ($item.PSIsContainer -or $item.Length -ne $entry.Length -or $item.LastWriteTimeUtc.Ticks -ne $entry.Modified -or $item.CreationTimeUtc.Ticks -ne $entry.Created -or $item.LastWriteTimeUtc -ge [DateTime]::UtcNow.AddDays(-14) -or $item.CreationTimeUtc -ge [DateTime]::UtcNow.AddDays(-14)) { throw 'Archivo cambiado o reciente.' }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop # Never recursive.
            if (Test-Path -LiteralPath $path) { throw 'El archivo sigue presente.' }
            $bytes+=$entry.Length; $deleted++
        } catch { $skipped++; Write-Warning $_.Exception.Message }
    }
    return [pscustomobject]@{ Deleted=$deleted; Skipped=$skipped; Bytes=$bytes; Reversible=$false }
}
function Get-DotNetTcpListeners {
    # Fuente independiente de CIM (GetTcpTable con estado LISTEN). Se usa para descartar filas que
    # Get-NetTCPConnection marque como Listen sin serlo (visto en builds Insider: PID 0, puertos efimeros).
    foreach($e in [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()){ ($e.Address.ToString() -replace '%.*$','')+'|'+$e.Port }
}
function Get-ListeningSockets {
    $real=$null
    try{$real=New-Object 'Collections.Generic.HashSet[string]';foreach($k in @(Get-DotNetTcpListeners)){$real.Add([string]$k)|Out-Null}}catch{$real=$null}
    foreach($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)){
        if([int]$c.OwningProcess -le 0){continue} # PID 0 = System Idle Process: conexiones cerradas/TIME_WAIT, nunca una escucha real.
        if($c.RemoteAddress -and [string]$c.RemoteAddress -notin @('0.0.0.0','::')){continue}
        if($c.RemotePort -and [int]$c.RemotePort -ne 0){continue}
        if($real -and $real.Count -and -not $real.Contains((([string]$c.LocalAddress) -replace '%.*$','')+'|'+$c.LocalPort)){continue}
        $c
    }
}
function Get-UacStatus {
    $p=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    [pscustomobject]@{EnableLUA=$p.EnableLUA;ConsentPromptBehaviorAdmin=$p.ConsentPromptBehaviorAdmin;PromptOnSecureDesktop=$p.PromptOnSecureDesktop;ProcessElevated=[bool](Test-IsAdmin)}
}
function Get-ElevationExplanation {
    $uac=$null;try{$uac=Get-UacStatus}catch{}
    if($uac -and $uac.EnableLUA -eq 0){return 'El Control de cuentas de usuario (UAC) esta desactivado: Windows abre todos los programas como administrador. Activarlo (ver resumen, opcion 1) y reiniciar.'}
    if($uac -and $uac.ConsentPromptBehaviorAdmin -eq 0){return 'UAC esta configurado para elevar sin preguntar: los programas de esta cuenta reciben permisos de administrador sin aviso. Subir UAC al nivel predeterminado.'}
    return 'Esta ventana se abrio como administrador (por ejemplo "Ejecutar como administrador" o una terminal elevada). Cerrarla y abrir "El Centinela de Windows.bat" con doble clic normal.'
}
function Invoke-Check($Id,[scriptblock]$Read) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try { $data=@(& $Read); return [pscustomobject]@{ Id=$Id; Status='Checked'; CheckedAt=[datetime]::UtcNow.ToString('o'); Data=$data; Error=$null; Seconds=$watch.Elapsed.TotalSeconds } }
    catch { return [pscustomobject]@{ Id=$Id; Status='Unavailable'; CheckedAt=[datetime]::UtcNow.ToString('o'); Data=@(); Error=$_.Exception.Message; Seconds=$watch.Elapsed.TotalSeconds } }
}
function Get-SecurityReport($PreviousReport) {
    $checks=@(
        Invoke-Check 'Windows' { Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15 | Select-Object Caption,Version,BuildNumber,LastBootUpTime }
        Invoke-Check 'Defender' { Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode,IsTamperProtected,AntivirusSignatureLastUpdated,QuickScanEndTime }
        Invoke-Check 'AntivirusProviders' { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -OperationTimeoutSec 15 | Select-Object displayName,productState }
        Invoke-Check 'AntivirusHealth' { Get-AntivirusHealth }
        Invoke-Check 'Firewall' { Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }
        Invoke-Check 'UAC' { Get-UacStatus }
        Invoke-Check 'ListeningTCP' { $names=@{};foreach($p in @(Get-Process -ErrorAction SilentlyContinue)){$names[[int]$p.Id]=$p.ProcessName}; Get-ListeningSockets | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Process';e={$names[[int]$_.OwningProcess]}} }
        Invoke-Check 'RunCurrentUser' { if(Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'){Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object * -ExcludeProperty PS*} }
        Invoke-Check 'Tasks' { Get-ScheduledTask | Select-Object TaskPath,TaskName,State,@{n='Actions';e={@($_.Actions | Select-Object Execute,Arguments)}} }
        Invoke-Check 'Services' { Get-CimInstance Win32_Service -OperationTimeoutSec 15 | Where-Object StartMode -eq Auto | Select-Object Name,State,PathName }
        Invoke-Check 'Apps' { Get-AppxPackage | Select-Object Name,Publisher,PackageFamilyName }
        Invoke-Check 'Privacy' { foreach($n in $script:PrivacyNames){ [pscustomobject]@{Name=$n;Value=(Read-PrivacyValue $n)} } }
    )
    if($PreviousReport){$checks+=@($PreviousReport.Checks|Where-Object {$_.Id -in @('NetworkInvestigation','Router','Support','Updates','CVE','IOC','ExternalProbe','PublicProbe')})}
    $report=[pscustomobject]@{ Schema=1; Version=$script:Version; Created=[DateTime]::UtcNow.ToString('o'); Sid=(Get-Identity); Checks=$checks; Gaps=@('La cobertura avanzada aparece como pendiente hasta ejecutar sus comprobaciones en la opcion 8.','Las pruebas externas importadas cubren solo la IP, puertos y fecha indicados.','El analisis IOC busca indicadores conocidos; no garantiza ausencia de compromiso.','La correlacion CVE se limita a KB pendientes y boletines Microsoft consultados, no todas las aplicaciones.') }
    if($PreviousReport -and $PreviousReport.PSObject.Properties['ActionHistory']){$report|Add-Member -MemberType NoteProperty -Name ActionHistory -Value @($PreviousReport.ActionHistory)}
    return Add-ReportAnalysis $report
}
function Export-Report($Report,[string]$Path) {
    Test-LocalPath $Path | Out-Null
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=[Text.Encoding]::UTF8.GetBytes((Protect-ExportText ($Report|ConvertTo-Json -Depth 10)));$stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
. (Join-Path $PSScriptRoot 'Summary.ps1')
. (Join-Path $PSScriptRoot 'DeepSecurity.ps1')
function Start-CentinelaMenu {
    Write-Host "El Centinela de Windows $script:Version - usuario: $(try{[Security.Principal.WindowsIdentity]::GetCurrent().Name}catch{[Environment]::UserName})"
    Write-Host 'Los cambios afectan esta cuenta. Ejecutar desde su sesion habitual; no requiere administrador. Cerrar instaladores antes de limpiar.'
    try{if(Test-IsAdmin){Write-Warning ('Centinela esta corriendo CON permisos de administrador. '+(Get-ElevationExplanation)+' El analisis IOC (8 > 6) no se ejecuta asi.')}}catch{}
    while ($true) {
        Show-MainMenu
        $choice=Read-Host 'Opcion'
        if (-not $choice -or $choice -eq '0') { return }
        try {
            switch ($choice) {
                '1' {
                    $script:LastReport=Get-SecurityReport $script:LastReport; Show-Report $script:LastReport
                    $follow=Read-Host '[E] Exportar al Escritorio / [S] Soluciones / [D] Detalle / Enter menu'
                    switch(([string]$follow).ToUpperInvariant()) {
                        'E' { Write-Host (Export-DesktopReport $script:LastReport) }
                        'S' { Show-Solutions $script:LastReport }
                        'D' { Show-Details $script:LastReport }
                    }
                }
                '2' {
                    $plan=@(New-PrivacyPlan); $plan | Format-Table Name,Before,After | Out-Host
                    Write-Host 'Ajustes de sugerencias por usuario; no modifica GPO/MDM ni garantiza persistencia tras actualizaciones. Conserva fotos de Spotlight. Puede requerir cerrar sesion.'
                    if ($plan.Count -and (Confirm-Choice 'Aplicar estos cambios con respaldo?')) {
                        $folder=Get-StateFolder; $path=Join-Path $folder ('privacy-'+[guid]::NewGuid().ToString('N')+'.json')
                        $result=Invoke-PrivacyPlan $plan $path
                        $result.Entries | Format-Table Name,Status | Out-Host; Write-Host "Respaldo: $path"
                    }
                }
                '3' {
                    $plan=@(Get-TempPlan); $plan | Format-Table Path,Length | Out-Host
                    Write-Host "$($plan.Count) archivos de mas de 14 dias. El borrado es permanente; no tiene deshacer. Solo Temp de esta cuenta; nunca carpetas completas."
                    if ($plan.Count -and (Confirm-Choice 'Eliminar exactamente los archivos listados?')) { Invoke-TempPlan $plan | Format-List | Out-Host }
                }
                '4' {
                    $folder=Get-StateFolder; $files=@(Get-ChildItem -LiteralPath $folder -Filter 'privacy-*.json' -File | Sort-Object LastWriteTime -Descending)
                    for($i=0;$i -lt $files.Count;$i++){Write-Host "[$i] $($files[$i].Name) $($files[$i].LastWriteTime)"}
                    $index=Read-Host 'Numero de respaldo (Enter cancela)'; $number=0
                    if ($index -ne '' -and [int]::TryParse($index,[ref]$number) -and $number -ge 0 -and $number -lt $files.Count -and (Confirm-Choice 'Restaurar ajustes de este respaldo?')) { (Undo-Privacy $files[$number].FullName).Entries | Format-Table Name,Status | Out-Host }
                }
                '5' {
                    if(-not $script:LastReport){Write-Host 'Primero ejecutar opcion 1.';continue}
                    Write-Host 'Se guardaran resumen TXT y detalle JSON del mismo diagnostico, con advertencias y acciones. El Escritorio puede estar sincronizado y el informe contiene datos privados.'
                    if(Confirm-Choice 'Exportar al Escritorio?'){Write-Host (Export-DesktopReport $script:LastReport)}
                }
                '6' {if($script:LastReport){Show-Details $script:LastReport}else{Write-Host 'Primero ejecutar opcion 1.'}}
                '8' {if($script:LastReport){Show-DeepMenu $script:LastReport}else{Write-Host 'Primero ejecutar opcion 1.'}}
                '7' {if($script:LastReport){Show-Solutions $script:LastReport}else{Write-Host 'Primero ejecutar opcion 1.'}}
            }
        } catch { Write-Warning $_.Exception.Message }
    }
}
if ($LibraryOnly) { return }
if ($Audit) {
    $report=Get-SecurityReport; Show-Report $report
    if ($ReportPath) { Export-Report $report $ReportPath }
    return
}
Start-CentinelaMenu
