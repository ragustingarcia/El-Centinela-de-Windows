$script:CheckTitles=@{Windows='Version de Windows';Defender='Microsoft Defender';AntivirusProviders='Proveedores antivirus';AntivirusHealth='Salud del antivirus';Firewall='Firewall de Windows';UAC='Control de cuentas (UAC)';ListeningTCP='Puertos abiertos';RunCurrentUser='Programas de inicio';Tasks='Tareas programadas';Services='Servicios';Apps='Aplicaciones';Privacy='Preferencias de publicidad';NetworkInvestigation='Red, procesos y puertos';Router='Router (UPnP)';Support='Soporte de Windows';Updates='Parches Windows';CVE='Correlacion CVE Microsoft';IOC='Indicadores de compromiso';ExternalProbe='Prueba externa importada';PublicProbe='Prueba externa mediante servicio'}
$script:AdvancedIds=@('NetworkInvestigation','Router','Support','Updates','CVE','IOC','ExternalProbe','PublicProbe')
# Puertos cuya apertura a la red merece explicacion propia. Clave: puerto; valor: nombre y si es base de datos/administracion.
$script:SensitivePorts=@{21='FTP';22='SSH (acceso remoto)';23='Telnet (acceso remoto sin cifrar)';1433='Base de datos SQL Server';1521='Base de datos Oracle';2375='API de Docker sin cifrar';2376='API de Docker';3306='Base de datos MySQL/MariaDB';3389='Escritorio remoto';5432='Base de datos PostgreSQL';5900='VNC (control remoto)';5938='TeamViewer';5985='WinRM (administracion remota)';5986='WinRM (administracion remota)';6379='Base de datos Redis';8080='Servidor web de desarrollo';9200='Elasticsearch';11211='Memcached';27017='Base de datos MongoDB'}
$script:WindowsProcessNames=@('System','svchost','svchost.exe','lsass','lsass.exe','wininit','wininit.exe','services','services.exe','spoolsv','spoolsv.exe','MsMpEng','MsMpEng.exe','NisSrv','NisSrv.exe','SearchIndexer','SearchIndexer.exe','msdtc','msdtc.exe','Idle','Registry')
function Get-CheckTitle($Id) { if($script:CheckTitles.ContainsKey([string]$Id)){return $script:CheckTitles[[string]$Id]}; return [string]$Id }
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
function Get-FailureAdvice($Id,$ErrorText) {
    $e=[string]$ErrorText
    if($e -match 'UPnP|router'){return 'El router no respondio por UPnP. Suele significar UPnP desactivado (es lo recomendable). Las redirecciones manuales solo se ven en la configuracion del router.'}
    if($e -match 'Tiempo|timeout|agotado'){return 'La consulta tardo demasiado. Repetir mas tarde o con mejor conexion.'}
    if($e -match '(?i)denegado|denied|acceso|permis|administrador|0x80070005'){return 'Faltan permisos. Repetir y aceptar el aviso de Windows (UAC) si aparece.'}
    if($e -match '(?i)red|network|internet|resolver|remote name|conex'){return 'Sin conexion con el servicio consultado. Revisar Internet y repetir.'}
    if($Id -in $script:AdvancedIds){return 'Repetir desde la opcion 8.'}
    return 'Repetir el diagnostico (opcion 1).'
}
function Get-ListenerScope($Address) {
    $a=[string]$Address
    if($a -eq '::1' -or $a -match '^127\.'){return 'Loopback'}
    if($a -in @('0.0.0.0','::')){return 'AllInterfaces'}
    return 'SingleInterface'
}
function Test-WindowsListener($Process,$Executable,$ProcessId) {
    if([int]$ProcessId -eq 4){return $true}
    if($Executable -and $env:SystemRoot -and ([string]$Executable).StartsWith($env:SystemRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){return $true}
    return (-not $Executable -and [string]$Process -in $script:WindowsProcessNames)
}
function Get-ListenerRisk($Port,$Scope,$IsSystemService) {
    # Devuelve nivel y explicacion corta en lenguaje llano.
    $name=$script:SensitivePorts[[int]$Port]
    if($IsSystemService){return [pscustomobject]@{Level='Info';Text='Servicio de Windows; normal en la mayoria de las PCs.'}}
    if($name){
        $lvl=if([int]$Port -eq 2375){'Alert'}else{'Review'}
        $where=if($Scope -eq 'AllInterfaces'){'cualquier equipo de tu red (o de un Wi-Fi publico)'}else{'otros equipos de esa red'}
        return [pscustomobject]@{Level=$lvl;Name=$name;Text="$name abierta a la red: $where puede intentar conectarse. Si solo la usas en esta PC, configurala para escuchar en localhost (127.0.0.1) o bloquea el puerto."}
    }
    if($Scope -eq 'SingleInterface' -and [int]$Port -ge 49152){return [pscustomobject]@{Level='Info';Text='Puerto temporal de la aplicacion; cambia en cada inicio.'}}
    if($Scope -eq 'AllInterfaces'){return [pscustomobject]@{Level='Review';Text='Abierto en todas las redes. Normal en juegos, chat o compartir; revisar si no reconoces el programa.'}}
    return [pscustomobject]@{Level='Info';Text='Abierto solo en la red local actual.'}
}
function Get-ReportAnalysis($Report) {
    $findings=New-Object 'Collections.Generic.List[object]'
    foreach($check in $Report.Checks) {
        if($check.Status -ne 'Checked') { $action=if($check.Id -in $script:AdvancedIds){'DeepChecks'}else{''};$findings.Add((New-Finding 'Unknown' (Get-CheckTitle $check.Id) ('No se pudo comprobar: '+$check.Error) $action (Get-FailureAdvice $check.Id $check.Error))) }
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
    $uac=@(Get-CheckData $Report 'UAC')
    if($uac.Count){
        $u=$uac[0]
        if($u.EnableLUA -eq 0){$findings.Add((New-Finding 'Alert' 'Control de cuentas (UAC) desactivado' 'Todo programa que abras corre como administrador: un programa malicioso tendria control total de Windows sin pedir permiso.' '' 'Panel de control > Cuentas de usuario > Cambiar configuracion de Control de cuentas de usuario: nivel predeterminado. Reiniciar.'))}
        elseif($u.ConsentPromptBehaviorAdmin -eq 0){$findings.Add((New-Finding 'Alert' 'UAC eleva sin preguntar' 'Los programas reciben permisos de administrador sin ningun aviso.' '' 'Subir UAC al nivel predeterminado en Cambiar configuracion de Control de cuentas de usuario.'))}
        elseif($u.PromptOnSecureDesktop -eq 0){$findings.Add((New-Finding 'Review' 'UAC sin escritorio seguro' 'El aviso de permisos no se muestra en el escritorio protegido; otro programa podria imitarlo o pulsarlo.' '' 'Subir UAC al nivel predeterminado.'))}
        else{$findings.Add((New-Finding 'OK' 'Control de cuentas (UAC)' 'Activo: los programas piden permiso antes de cambiar Windows.'))}
    }
    $listeners=@(Get-CheckData $Report 'ListeningTCP'|Where-Object { $_.LocalAddress -and [int]$_.OwningProcess -ne 0 -and (Get-ListenerScope $_.LocalAddress) -ne 'Loopback' })
    $groups=@($listeners|Group-Object {[string]$_.OwningProcess+'|'+$_.LocalPort})
    $other=New-Object 'Collections.Generic.List[string]';$otherReview=$false
    foreach($g in $groups){
        $l=$g.Group[0];$scope=if(@($g.Group|Where-Object {(Get-ListenerScope $_.LocalAddress) -eq 'AllInterfaces'}).Count){'AllInterfaces'}else{'SingleInterface'}
        $proc=if($l.PSObject.Properties['Process'] -and $l.Process){[string]$l.Process}else{'PID '+$l.OwningProcess}
        $risk=Get-ListenerRisk $l.LocalPort $scope (Test-WindowsListener $proc $null $l.OwningProcess)
        if($risk.Name){$findings.Add((New-Finding $risk.Level ("$($risk.Name) abierta a la red (puerto $($l.LocalPort))") "Programa: $proc. Direcciones: $((@($g.Group|ForEach-Object {[string]$_.LocalAddress}|Select-Object -Unique)) -join ' y '). $($risk.Text)" 'InspectNetwork' 'Opcion 8 > 1: ver el programa y, si queres, bloquear el puerto con una regla reversible.'))}
        elseif($risk.Level -eq 'Review'){$otherReview=$true;$other.Add("$proc ($($l.LocalPort))")}
        elseif($risk.Level -eq 'Info' -and $risk.Text -notlike 'Servicio de Windows*'){$other.Add("$proc ($($l.LocalPort))")}
    }
    if($other.Count){
        $names=@($other|Select-Object -Unique)
        $findings.Add((New-Finding $(if($otherReview){'Review'}else{'Info'}) 'Programas con puertos abiertos a la red' ("$($names.Count): "+(($names|Select-Object -First 8) -join ', ')+$(if($names.Count -gt 8){' ...'}else{''})+'. Normal en juegos, chat y apps de sincronizacion; no demuestra exposicion a Internet.') 'InspectNetwork' 'Opcion 8 > 1 para ver cada programa y bloquear el que no reconozcas.'))
    }
    $privacy=@(Get-CheckData $Report 'Privacy'|Where-Object {$null -eq $_.Value -or $_.Value -ne 0})
    if($privacy.Count){$findings.Add((New-Finding 'Info' 'Preferencias de publicidad' ("$($privacy.Count) ajustes de sugerencias/publicidad siguen activos. No es un riesgo de seguridad.") 'Privacy' 'Usar Reducir publicidad (opcion 2), con respaldo y deshacer.'))}
    $health=@(Get-CheckData $Report 'AntivirusHealth')
    if($health.Count){$findings.Add((New-Finding $(if($health[0].Code -eq 0){'OK'}else{'Review'}) 'Salud de proveedor antivirus' ([string]$health[0].Health) '' $(if($health[0].Code -eq 0){''}else{$health[0].Scope})))}
    $imported=@($Report.Checks|Where-Object { $_.Id -eq 'ExternalProbe' -and $_.Status -eq 'Checked' }).Count -gt 0
    $pending=New-Object 'Collections.Generic.List[string]'
    foreach($id in $script:AdvancedIds) {
        $title=Get-CheckTitle $id
        $checks=@($Report.Checks|Where-Object Id -eq $id)
        if(-not $checks.Count){
            if($id -eq 'ExternalProbe' -or ($id -eq 'PublicProbe' -and $imported)){continue}
            $pending.Add($title);continue
        }
        if($checks[0].Status -ne 'Checked'){continue}
        $data=@($checks[0].Data);if(-not $data.Count){$findings.Add((New-Finding 'Unknown' $title 'La consulta no devolvio evidencia interpretable.' 'DeepChecks' 'Repetir desde opcion 8.'));continue}
        $d=$data[0];$level='Info';$detail='Resultado guardado con su alcance. Revisar detalle para interpretar.'
        switch($id){
            'NetworkInvestigation' {
                $net=@($d.Listeners|Where-Object {$_.Scope -ne 'Loopback' -and -not $_.IsWindows})
                $level='Info'
                $detail="$($net.Count) programas no-Windows aceptan conexiones desde la red. Ver los puntos de puertos de este resumen."
                if($d.ActionResult){$detail+=' | Accion: '+$d.ActionResult.Status+' '+$d.ActionResult.Detail}
                if($d.VPNProfiles -and $d.VPNProfiles.Status -ne 'Checked'){$findings.Add((New-Finding 'Unknown' 'Perfiles VPN Windows' $d.VPNProfiles.Error 'DeepChecks' 'Revisar cliente/permisos. Los adaptadores se inventarian por separado.'))}
                foreach($row in @($d.Listeners|Where-Object {$_.Scope -ne 'Loopback' -and -not $_.IsWindows -and $_.Risk -and $_.Risk.Name})){
                    if(-not @($findings|Where-Object Title -like "*(puerto $($row.Port))").Count){$findings.Add((New-Finding $row.Risk.Level ("$($row.Risk.Name) abierta a la red (puerto $($row.Port))") "Programa: $($row.Process). Direcciones: $($row.Address). $($row.Risk.Text)" 'InspectNetwork' 'Opcion 8 > 1: ver el programa y, si queres, bloquear el puerto con una regla reversible.'))}
                }
            }
            'Router' {
                if($d.PSObject.Properties['UPnPAvailable'] -and -not $d.UPnPAvailable){$level='OK';$detail='El router no ofrece UPnP a esta PC: los programas no pueden abrir puertos en el router por su cuenta. '+$d.Scope}
                else{$count=@($d.Mappings|Where-Object Enabled -eq $true).Count;$level=if($count){'Review'}else{'OK'};$detail="$count puertos abiertos automaticamente en el router (UPnP). "+$(if($count){'Cada uno expone un servicio de tu red a Internet; revisar que los reconozcas. '}else{''})+$d.Scope}
            }
            'Support' {$level=if($d.Status -eq 'InSupportUntil'){'OK'}elseif($d.Status -eq 'StandardSupportEnded'){'Review'}elseif($d.Status -eq 'Insider'){'Info'}else{'Unknown'};$detail=$(if($d.Status -eq 'Insider'){$d.Detail}else{'Estado: '+$d.Status+' | Fin observado: '+$d.EndDate+' | Fuente: '+$d.Source+' | '+$d.Detail})}
            'Updates' {
                $count=@($d.Updates).Count;$security=@($d.Updates|Where-Object Security -eq $true).Count
                $level=if($security){'Alert'}elseif($count -or $d.RebootRequired){'Review'}else{'OK'}
                $detail="$count parches ofrecidos; $security de seguridad. Reinicio requerido: $($d.RebootRequired). "+$d.Scope
            }
            'CVE' {
                $level=if(@($d.Gaps).Count){'Unknown'}elseif(@($d.Matches).Count){'Review'}else{'Info'}
                $detail=[string]@($d.Matches).Count+' correlaciones KB/CVE; '+@($d.Sources).Count+' fuentes consultadas. '+$d.Scope
                if(@($d.Gaps).Count){$detail+=' | Fuentes pendientes: '+($d.Gaps -join '; ')}
            }
            'IOC' {
                $level=if($d.ExitCode -eq 2){'Alert'}elseif($d.ExitCode -eq 3){'Unknown'}else{'Info'}
                $detail='Exit code: '+$d.ExitCode+' | '+($d.Verdict|ConvertTo-Json -Compress -Depth 4)
                foreach($caveat in $d.Caveats){$text=if($caveat.text){$caveat.text}else{[string]$caveat};$findings.Add((New-Finding 'Info' 'Alcance IOC' $text))}
            }
            'ExternalProbe' {$level=if(@($d.Results|Where-Object Status -eq Reachable).Count){'Review'}else{'Info'};$detail=$d.Target+' | '+$d.At+' | '+$d.Provenance+' | '+$d.Scope}
            'PublicProbe' {
                $level='Info';$detail='Muestras externas conservadas: '+$data.Count
                foreach($probe in ($data|Group-Object Target,Family,Port|ForEach-Object {$_.Group[-1]})){
                    $probeLevel=if($probe.Status -in @('Pending','Unknown')){'Unknown'}elseif($probe.Status -eq 'Reachable'){'Review'}else{'Info'}
                    $findings.Add((New-Finding $probeLevel 'Resultado externo TCP' ($probe.Target+':'+$probe.Port+' - '+$probe.Status+' | '+$probe.At+' | '+$probe.EvidenceLink) 'DeepChecks' $probe.Scope))
                }
            }
        }
        $detail+=' | Observado: '+$checks[0].CheckedAt
        $findings.Add((New-Finding $level $title $detail 'DeepChecks' $(if($level -in @('OK','Info')){''}else{'Ver evidencia y siguientes acciones en opcion 8.'})))
    }
    if($pending.Count){$findings.Add((New-Finding 'Pending' 'Comprobaciones avanzadas sin hacer' ($pending -join ', ') 'DeepChecks' 'Opcional: opcion 8. Las consultas por Internet piden confirmacion antes.'))}
    $alerts=@($findings|Where-Object Level -eq Alert).Count;$reviews=@($findings|Where-Object Level -eq Review).Count;$unknown=@($findings|Where-Object Level -eq Unknown).Count
    $coreIds=@('Defender','Firewall')
    $coreMissing=@($Report.Checks|Where-Object {$_.Id -in $coreIds -and $_.Status -ne 'Checked'}).Count -gt 0
    $state=if($alerts){'EN RIESGO'}elseif($reviews -or $coreMissing){'REVISAR'}else{'SEGURA'}
    $plain=switch($state){
        'EN RIESGO' {"Hay $alerts problema(s) que dejan la PC desprotegida. Resolverlos primero."}
        'REVISAR' {if($coreMissing){'No se pudo confirmar el antivirus o el firewall. Repetir el diagnostico.'}else{"La proteccion basica esta activa, pero hay $reviews punto(s) para revisar."}}
        default {'Antivirus, firewall y configuracion basica en orden.'+$(if($unknown){" ($unknown dato(s) no se pudieron leer.)"}else{''})}
    }
    $verdict=switch($state){'EN RIESGO'{'Hay configuraciones de proteccion que requieren atencion prioritaria.'}'REVISAR'{'Proteccion basica activa con puntos para revisar.'}default{'Sin alertas en los controles interpretados.'}}
    [pscustomobject]@{
        State=$state
        Plain=$plain
        Verdict=$verdict
        Generated=[datetime]::UtcNow.ToString('o')
        Alerts=$alerts
        Review=$reviews
        Unknown=$unknown
        Pending=$pending.Count
        OK=@($findings|Where-Object Level -eq OK).Count
        Findings=$findings.ToArray()
        Conclusion='Los resultados describen lo observado en las fuentes y fechas indicadas; no garantizan ausencia de compromiso.'
    }
}
function Add-ReportAnalysis($Report) {
    $Report|Add-Member -MemberType NoteProperty -Name Analysis -Value (Get-ReportAnalysis $Report) -Force
    return $Report
}
function Get-ReportText($Report,[switch]$Full) {
    $a=$Report.Analysis
    $created=Convert-ObservedDate $Report.Created
    $when=if($created.Year -gt 2000){$created.ToLocalTime().ToString('dd/MM/yyyy HH:mm')}else{[string]$Report.Created}
    $state=if($a.PSObject.Properties['State']){$a.State}else{'REVISAR'}
    $plainText=if($a.PSObject.Properties['Plain']){$a.Plain}else{$a.Verdict}
    $lines=@("EL CENTINELA DE WINDOWS $($Report.Version) - $when",'',"VEREDICTO: $state",('  '+$plainText),'')
    $problems=@($a.Findings|Where-Object {$_.Level -in @('Alert','Review')}|Sort-Object @{e={if($_.Level -eq 'Alert'){0}else{1}}})
    if($problems.Count){
        $lines+='PARA RESOLVER / REVISAR'
        foreach($f in $problems){$mark=if($f.Level -eq 'Alert'){'[!!]'}else{'[!] '};$lines+="  $mark $($f.Title)";$lines+="       $($f.Detail)";if($f.Advice){$lines+="       Que hacer: $($f.Advice)"}}
        $lines+=''
    }
    $ok=@($a.Findings|Where-Object Level -eq OK|ForEach-Object Title)
    $fw=@($ok|Where-Object {$_ -match '^Firewall '}|ForEach-Object {$_ -replace '^Firewall ',''})
    if($fw.Count -gt 1){$ok=@($ok|Where-Object {$_ -notmatch '^Firewall '})+@('Firewall ('+($fw -join ', ')+')')}
    if($ok.Count){$lines+='BIEN';$lines+='  '+($ok -join ', ')+'.';$lines+=''}
    $unk=@($a.Findings|Where-Object Level -eq Unknown)
    if($unk.Count){$lines+='NO SE PUDO COMPROBAR';foreach($f in $unk){$lines+="  - $($f.Title): $($f.Detail)";if($f.Advice){$lines+="    $($f.Advice)"}};$lines+=''}
    $info=@($a.Findings|Where-Object {$_.Level -in @('Info','Pending')})
    if($info.Count){$lines+='PARA TU INFORMACION';foreach($f in $info){$lines+="  - $($f.Title): $($f.Detail)"};$lines+=''}
    if($Report.PSObject.Properties['ActionHistory'] -and @($Report.ActionHistory).Count) {
        $lines+='ACCIONES Y RESULTADOS'
        foreach($h in $Report.ActionHistory){$lines+="  $($h.Action) [$($h.Status)] $($h.Detail)"}
        $lines+=''
    }
    if($Full){
        $lines+='INVENTARIO Y CONTEXTO'
        foreach($id in @('Windows','RunCurrentUser','Tasks','Services','Apps')) {
            $c=@($Report.Checks|Where-Object Id -eq $id)
            if($c.Count -ne 1 -or $c[0].Status -ne 'Checked'){continue}
            if($id -eq 'Windows' -and @($c[0].Data).Count){$os=$c[0].Data[0];$lines+="Windows: $($os.Caption), build $($os.BuildNumber)."}
            elseif($id -eq 'RunCurrentUser'){
                $names=@($c[0].Data|ForEach-Object {$_.PSObject.Properties.Name}|Where-Object {$_ -notmatch '^PS'})
                $lines+='Inicio de esta cuenta: '+$names.Count+' entradas. '+($names -join ', ')
            }else{$lines+=(Get-CheckTitle $id)+': '+@($c[0].Data).Count+' elementos inventariados.'}
        }
        $lines+=@('','LIMITES')+@($Report.Gaps)+@($a.Conclusion)
    } else {
        $lines+='Limites: '+$a.Conclusion
    }
    return (($lines -join [Environment]::NewLine) -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]','?')
}
function Protect-ExportText([string]$Text) {
    # Oculta credenciales que algunos programas dejan en argumentos de tareas/servicios antes de exportar.
    return [regex]::Replace($Text,'(?i)((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*)("?)[^\s"\\,;]+','$1$2[oculto]')
}
function Show-Report($Report) {
    Write-Host "`n==============================================================" -ForegroundColor Cyan
    Write-Host (Get-ReportText $Report)
    Write-Host '==============================================================' -ForegroundColor Cyan
}
function Show-Details($Report) {
    foreach($c in $Report.Checks){Write-Host "`n[$($c.Status)] $(Get-CheckTitle $c.Id) ($($c.Id))";if($c.Error){Write-Warning $c.Error}else{($c.Data|Format-List|Out-String) -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]','?'|Out-Host}}
}
function Get-DesktopFolder { [Environment]::GetFolderPath('DesktopDirectory') }
function Export-DesktopReport($Report) {
    # Known Folder API handles redirected/OneDrive desktops. No elevation and no arbitrary destination input.
    $desktop=Get-DesktopFolder
    if(-not $desktop -or -not (Test-Path -LiteralPath $desktop -PathType Container)){throw 'Escritorio no disponible.'}
    $folder=Join-Path $desktop ('Centinela-'+[datetime]::Now.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    [IO.Directory]::CreateDirectory($folder)|Out-Null
    foreach($name in @('Resumen.txt','Diagnostico.json')) {
        $content=Protect-ExportText $(if($name -eq 'Resumen.txt'){Get-ReportText $Report -Full}else{$Report|ConvertTo-Json -Depth 15})
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
    $items=@($Report.Analysis.Findings|Where-Object {$_.Level -in @('Alert','Review','Unknown','Pending')}|Sort-Object @{e={@{Alert=0;Review=1;Unknown=2;Pending=3}[[string]$_.Level]}})
    if(-not $items.Count){Write-Host 'No hay correcciones propuestas por los controles disponibles.';return}
    for($i=0;$i -lt $items.Count;$i++){Write-Host "[$($i+1)] $($items[$i].Title)";if($items[$i].Advice){Write-Host ('    '+$items[$i].Advice)}}
    $answer=Read-Host 'Numero de propuesta (Enter vuelve)';$index=0
    if(-not [int]::TryParse($answer,[ref]$index) -or $index -lt 1 -or $index -gt $items.Count){return}
    $item=$items[$index-1]
    if($item.Action -eq 'InspectNetwork'){Add-DeepResult $Report 'NetworkInvestigation' {Show-NetworkInvestigation};return}
    if($item.Action -eq 'DeepChecks'){Show-DeepMenu $Report;return}
    if($item.Action -eq 'Privacy'){Write-Host 'Usar opcion 2 del menu: vista previa, respaldo y deshacer.';return}
    if(-not $item.Action){Write-Host $item.Advice;return}
    Write-Host 'Se aplica solo la accion elegida. Puede requerir permisos, descargar definiciones o iniciar un analisis con remediacion de Defender. No modifica exclusiones ni desactiva protecciones.'
    if(Confirm-Choice ('Ejecutar '+$item.Title+'?')) {
        $result=if(Test-IsAdmin){Invoke-SecuritySolution $item.Action}else{Invoke-ElevatedSecurity $item.Action @{}}
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
    Write-Host '  [8] Seguridad avanzada: red, router, parches, CVE e IOC'
    Write-Host '  [0] Salir'
    Write-Host '  ----------------------------------------------------------'
}
