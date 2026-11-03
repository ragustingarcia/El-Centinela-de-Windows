function Get-CheckData($Report,$Id) {
    $check=@($Report.Checks | Where-Object Id -eq $Id)
    if ($check.Count -eq 1 -and $check[0].Status -eq 'Checked') { return $check[0].Data }
}
function New-Finding($Level,$Title,$Detail,$Action='',$Advice='') {
    [pscustomobject]@{Level=$Level;Title=$Title;Detail=$Detail;Action=$Action;Advice=$Advice}
}
function Convert-ObservedDate($Value) {
    if($Value -is [datetime]){return $Value}
    $date=[datetime]::MinValue
    if([datetime]::TryParse([string]$Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$date)){return $date}
    return [datetime]::MinValue
}
function Get-ReportAnalysis($Report) {
    $findings=New-Object 'Collections.Generic.List[object]'
    foreach($check in $Report.Checks) {
        if($check.Status -ne 'Checked') { $findings.Add((New-Finding 'Unknown' $check.Id ('No se pudo comprobar: '+$check.Error) '' 'Revisar permisos y repetir el diagnostico.')) }
    }
    $d=@(Get-CheckData $Report 'Defender')
    if($d.Count) {
        $d=$d[0]
        if($d.AMRunningMode -eq 'Normal') {
            if($d.RealTimeProtectionEnabled -eq $true -and $d.AntivirusEnabled -eq $true) {
                $findings.Add((New-Finding 'OK' 'Antivirus' 'Defender informa antivirus y proteccion en tiempo real activos.'))
            } elseif($d.RealTimeProtectionEnabled -eq $false) {
                $findings.Add((New-Finding 'Alert' 'Proteccion en tiempo real inactiva' 'Defender esta en modo Normal pero no informa proteccion en tiempo real.' 'EnableRealtime' 'Proponer activacion y verificar el estado; puede requerir administrador.'))
            } else { $findings.Add((New-Finding 'Unknown' 'Antivirus' 'El estado devuelto no permite confirmar todas las protecciones.')) }
        } else { $findings.Add((New-Finding 'Review' 'Proveedor antivirus' 'Defender no informa modo Normal; puede existir otro antivirus. No se fuerza su activacion.' '' 'Comprobar el proveedor activo en Seguridad de Windows.')) }
        if($d.IsTamperProtected -eq $true) { $findings.Add((New-Finding 'OK' 'Proteccion contra alteraciones' 'Windows informa Tamper Protection habilitada.')) }
        elseif($d.IsTamperProtected -eq $false){$findings.Add((New-Finding 'Review' 'Proteccion contra alteraciones desactivada' 'La configuracion informa proteccion desactivada.' '' 'Revisar Proteccion contra alteraciones en Seguridad de Windows.'))}
        else {$findings.Add((New-Finding 'Unknown' 'Proteccion contra alteraciones' 'Estado no disponible.'))}
        $date=Convert-ObservedDate $d.AntivirusSignatureLastUpdated
        if($date.Year -gt 2000) {
            $age=([datetime]::UtcNow-$date.ToUniversalTime()).TotalDays
            if($age -lt -1){$findings.Add((New-Finding 'Unknown' 'Fecha de firmas' 'La fecha esta en el futuro; revisar el reloj del sistema.'))}
            elseif($age -gt 3){$findings.Add((New-Finding 'Review' 'Firmas antiguas' ('Ultima actualizacion: '+$date) 'UpdateSignatures' 'Actualizar las definiciones y verificar la nueva fecha.'))}
            else{$findings.Add((New-Finding 'OK' 'Firmas recientes' ('Actualizadas: '+$date)))}
        } else {$findings.Add((New-Finding 'Unknown' 'Fecha de firmas' 'No se pudo determinar la antiguedad de las definiciones.'))}
        $scan=Convert-ObservedDate $d.QuickScanEndTime
        if($scan.Year -lt 2001 -or ([datetime]::Now-$scan).TotalDays -gt 7) {
            $findings.Add((New-Finding 'Review' 'Analisis rapido pendiente de revisar' 'No hay un analisis rapido reciente dentro de los ultimos 7 dias. Esto no demuestra infeccion.' 'QuickScan' 'Proponer un analisis rapido. Puede consumir recursos y remediar detecciones segun Defender.'))
        }
    } elseif(@($Report.Checks|Where-Object { $_.Id -eq 'Defender' -and $_.Status -eq 'Checked' }).Count) {
        $findings.Add((New-Finding 'Unknown' 'Defender' 'La consulta no devolvio datos de proteccion.'))
    }
    $profiles=@(Get-CheckData $Report 'Firewall')
    if($profiles.Count) {
        foreach($p in $profiles) {
            if([string]$p.Enabled -eq 'True') {$findings.Add((New-Finding 'OK' ('Firewall '+$p.Name) 'Perfil informado como habilitado.'))}
            elseif([string]$p.Enabled -eq 'False') {$findings.Add((New-Finding 'Alert' ('Firewall '+$p.Name+' desactivado') 'Este perfil no protege el trafico con el firewall de Windows.' '' 'Activar desde Seguridad de Windows > Firewall. Se requiere revisar red y politicas antes de automatizar este cambio.'))}
            else {$findings.Add((New-Finding 'Unknown' ('Firewall '+$p.Name) 'Estado efectivo no determinado.'))}
            if([string]$p.DefaultInboundAction -eq 'Allow') {$findings.Add((New-Finding 'Review' ('Entrada permitida en '+$p.Name) 'La accion entrante predeterminada permite conexiones.' '' 'Revisar reglas y politica de red; no cerrar accesos administrativos sin comprobar dependencias.'))}
        }
    } elseif(@($Report.Checks|Where-Object { $_.Id -eq 'Firewall' -and $_.Status -eq 'Checked' }).Count) {
        $findings.Add((New-Finding 'Unknown' 'Firewall' 'La consulta termino sin devolver perfiles; no acredita proteccion.'))
    }
    $listeners=@(Get-CheckData $Report 'ListeningTCP')
    $nonlocal=@($listeners|Where-Object { $_.LocalAddress -and $_.LocalAddress -ne '::1' -and $_.LocalAddress -notmatch '^127\.' })
    if($nonlocal.Count){$findings.Add((New-Finding 'Review' 'Servicios escuchando en interfaces de red' ("$($nonlocal.Count) escuchas fuera de loopback. Su alcance depende de firewall, router y red; no prueban exposicion a Internet.") '' 'Revisar puertos y procesos en Detalle tecnico. No se cierran automaticamente.'))}
    $privacy=@(Get-CheckData $Report 'Privacy'|Where-Object {$null -eq $_.Value -or $_.Value -ne 0})
    if($privacy.Count){$findings.Add((New-Finding 'Review' 'Preferencias de publicidad' ("$($privacy.Count) ajustes no estan explicitamente desactivados; ausencia no demuestra publicidad activa.") 'Privacy' 'Usar Reducir publicidad, con respaldo y deshacer.'))}
    $verdict=if(@($findings|Where-Object Level -eq Alert).Count){'Hay configuraciones de proteccion que requieren atencion prioritaria.'}elseif(@($findings|Where-Object Level -eq Unknown).Count){'Diagnostico parcial: hay controles que no se pudieron confirmar.'}else{'Sin alertas en los controles interpretados. Revisar las recomendaciones y los limites de cobertura.'}
    [pscustomobject]@{
        Verdict=$verdict
        Generated=[datetime]::UtcNow.ToString('o')
        Alerts=@($findings|Where-Object Level -eq Alert).Count
        Review=@($findings|Where-Object Level -eq Review).Count
        Unknown=@($findings|Where-Object Level -eq Unknown).Count
        OK=@($findings|Where-Object Level -eq OK).Count
        Findings=$findings.ToArray()
        Conclusion='Sin garantia de ausencia de compromiso. Los hallazgos son configuraciones y senales observadas; no un escaneo completo de vulnerabilidades/CVE.'
    }
}
function Add-ReportAnalysis($Report) {
    $Report|Add-Member -MemberType NoteProperty -Name Analysis -Value (Get-ReportAnalysis $Report) -Force
    return $Report
}
function Get-ReportText($Report) {
    $a=$Report.Analysis
    $lines=@('EL CENTINELA DE WINDOWS - RESUMEN',"Version: $($Report.Version) | Diagnostico: $($Report.Created)",$a.Verdict,"Alertas: $($a.Alerts) | Revisar: $($a.Review) | Sin comprobar: $($a.Unknown) | Favorables: $($a.OK)",'')
    $labels=@{OK='FAVORABLE';Alert='ALERTA';Review='REVISAR';Unknown='SIN COMPROBAR'}
    foreach($f in $a.Findings){$lines+="[$($labels[$f.Level])] $($f.Title): $($f.Detail)";if($f.Advice){$lines+='  Propuesta: '+$f.Advice}}
    $lines+=@('','INVENTARIO Y CONTEXTO')
    foreach($id in @('Windows','RunCurrentUser','Tasks','Services','Apps')) {
        $c=@($Report.Checks|Where-Object Id -eq $id)
        if($c.Count -ne 1 -or $c[0].Status -ne 'Checked'){continue}
        if($id -eq 'Windows' -and @($c[0].Data).Count){$os=$c[0].Data[0];$lines+="Windows: $($os.Caption), build $($os.BuildNumber). Soporte y CVE no comprobados."}
        elseif($id -eq 'RunCurrentUser'){
            $names=@($c[0].Data|ForEach-Object {$_.PSObject.Properties.Name}|Where-Object {$_ -notmatch '^PS'})
            $lines+='Inicio de esta cuenta: '+$names.Count+' entradas. '+($names -join ', ')
        }else{$lines+=$id+': '+@($c[0].Data).Count+' elementos inventariados. Detalle disponible; su presencia no demuestra software innecesario o malicioso.'}
    }
    $lines+=@('','LIMITES Y ADVERTENCIAS')+@($Report.Gaps)+@($a.Conclusion)
    if($Report.PSObject.Properties['ActionHistory']) {
        $lines+=@('','ACCIONES Y RESULTADOS')
        foreach($h in $Report.ActionHistory){$lines+="$($h.Action) [$($h.Status)] $($h.Detail)"}
    }
    return (($lines -join [Environment]::NewLine) -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]','?')
}
function Show-Report($Report) {
    Write-Host "`n==============================================================" -ForegroundColor Cyan
    Write-Host (Get-ReportText $Report)
    Write-Host '==============================================================' -ForegroundColor Cyan
}
function Show-Details($Report) {
    foreach($c in $Report.Checks){Write-Host "`n[$($c.Status)] $($c.Id)";if($c.Error){Write-Warning $c.Error}else{($c.Data|Format-List|Out-String) -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]','?'|Out-Host}}
}
function Get-DesktopFolder { [Environment]::GetFolderPath('DesktopDirectory') }
function Export-DesktopReport($Report) {
    # Known Folder API handles redirected/OneDrive desktops. No elevation and no arbitrary destination input.
    $desktop=Get-DesktopFolder
    if(-not $desktop -or -not (Test-Path -LiteralPath $desktop -PathType Container)){throw 'Escritorio no disponible.'}
    $folder=Join-Path $desktop ('Centinela-'+[datetime]::Now.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    [IO.Directory]::CreateDirectory($folder)|Out-Null
    foreach($name in @('Resumen.txt','Diagnostico.json')) {
        $content=if($name -eq 'Resumen.txt'){Get-ReportText $Report}else{$Report|ConvertTo-Json -Depth 15}
        $stream=[IO.File]::Open((Join-Path $folder $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$bytes=[Text.Encoding]::UTF8.GetBytes($content);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
    }
    return $folder
}
function Test-IsAdmin {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-SecuritySolution([string]$Action) {
    if($Action -notin @('UpdateSignatures','QuickScan','EnableRealtime')){throw 'Accion no permitida.'}
    $result=[pscustomobject]@{Action=$Action;At=[datetime]::UtcNow.ToString('o');Status='Failed';Detail=''}
    try {
        $before=Get-MpComputerStatus -ErrorAction Stop
        if($before.AMRunningMode -ne 'Normal'){throw 'Defender no esta en modo Normal. Revisar proveedor activo; no se fuerza el cambio.'}
        switch($Action){
            'UpdateSignatures' {
                Update-MpSignature -ErrorAction Stop
                $after=Get-MpComputerStatus -ErrorAction Stop
                $date=[datetime]$after.AntivirusSignatureLastUpdated
                if($date.Year -le 2000 -or ([datetime]::UtcNow-$date.ToUniversalTime()).TotalDays -gt 3 -or $date.ToUniversalTime() -gt [datetime]::UtcNow.AddDays(1)){throw 'Definiciones recientes no verificadas.'}
                $result.Status='Verified';$result.Detail='Definiciones recientes verificadas: '+$date
            }
            'QuickScan' {
                $requested=[datetime]::Now
                Start-MpScan -ScanType QuickScan -ErrorAction Stop
                $after=Get-MpComputerStatus -ErrorAction Stop
                if($after.QuickScanEndTime -and $after.QuickScanEndTime -ge $requested -and $after.QuickScanEndTime -gt $before.QuickScanEndTime){$result.Status='Completed';$result.Detail='Finalizacion nueva registrada. Revisar detecciones en Seguridad de Windows; no equivale a PC libre de infeccion.'}
                else{$result.Status='Requested';$result.Detail='Solicitud enviada; finalizacion no verificada. Revisar Seguridad de Windows.'}
            }
            'EnableRealtime' {
                if(-not (Test-IsAdmin)){ $result.Status='NeedsAdmin';$result.Detail='Abrir Seguridad de Windows y activar Proteccion en tiempo real. No se eleva automaticamente ni se cambia la cuenta.';return $result }
                if($before.RealTimeProtectionEnabled -eq $true){$result.Status='AlreadyOK';$result.Detail='La proteccion ya esta activa.';return $result}
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                $after=Get-MpComputerStatus -ErrorAction Stop
                if($after.RealTimeProtectionEnabled -ne $true){throw 'Activacion no verificada; una politica o Tamper Protection puede impedir cambios. No se evita esa proteccion.'}
                $result.Status='Verified';$result.Detail='Proteccion en tiempo real activa, comprobada despues del cambio.'
            }
        }
    } catch{$result.Detail=$_.Exception.Message}
    return $result
}
function Show-Solutions($Report) {
    $items=@($Report.Analysis.Findings|Where-Object {$_.Level -in @('Alert','Review')})
    if(-not $items.Count){Write-Host 'No hay correcciones propuestas por los controles disponibles.';return}
    for($i=0;$i -lt $items.Count;$i++){Write-Host "[$($i+1)] $($items[$i].Title)";Write-Host ('    '+$items[$i].Advice)}
    $answer=Read-Host 'Numero de propuesta (Enter vuelve)';$index=0
    if(-not [int]::TryParse($answer,[ref]$index) -or $index -lt 1 -or $index -gt $items.Count){return}
    $item=$items[$index-1]
    if($item.Action -eq 'Privacy'){Write-Host 'Usar opcion 2 del menu: vista previa, respaldo y deshacer.';return}
    if(-not $item.Action){Write-Host $item.Advice;return}
    Write-Host 'Se aplica solo la accion elegida. Puede requerir permisos, descargar definiciones o iniciar un analisis con remediacion de Defender. No modifica exclusiones ni desactiva protecciones.'
    if(Confirm-Choice ('Ejecutar '+$item.Title+'?')) {
        $result=Invoke-SecuritySolution $item.Action
        if(-not $Report.PSObject.Properties['ActionHistory']){$Report|Add-Member -MemberType NoteProperty -Name ActionHistory -Value @()}
        $Report.ActionHistory=@($Report.ActionHistory)+@($result)
        $result|Format-List|Out-Host
        Write-Host 'El diagnostico conserva su fecha original. Volver a ejecutar opcion 1 para actualizar el resumen; exportar conserva tambien este resultado.'
    }
}
function Show-MainMenu {
    Write-Host "`n  EL CENTINELA DE WINDOWS $script:Version" -ForegroundColor Cyan
    Write-Host '  ----------------------------------------------------------'
    Write-Host '  [1] Diagnostico general y resumen'
    Write-Host '  [2] Reducir publicidad (con respaldo)'
    Write-Host '  [3] Limpiar temporales antiguos'
    Write-Host '  [4] Deshacer cambios de privacidad'
    Write-Host '  [5] Exportar ultimo diagnostico al Escritorio'
    Write-Host '  [6] Ver detalle tecnico del ultimo diagnostico'
    Write-Host '  [7] Soluciones propuestas y acciones automaticas'
    Write-Host '  [0] Salir'
    Write-Host '  ----------------------------------------------------------'
}
