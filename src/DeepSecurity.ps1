# Online checks are explicit actions, never part of an ordinary offline inventory.
function Get-AntivirusHealth {
    if(-not ('Centinela.WscHealth' -as [type])){
        Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; namespace Centinela { public static class WscHealth { [DllImport("wscapi.dll")] public static extern int WscGetSecurityProviderHealth(uint providers, out int health); }}'
    }
    $health=0;$hr=[Centinela.WscHealth]::WscGetSecurityProviderHealth(4,[ref]$health)
    if($hr -ne 0){throw "Windows Security Center no dio salud verificable (HRESULT $hr)."}
    [pscustomobject]@{Code=$health;Health=@('Good','NotMonitored','Poor','Snoozed')[$health];Source='Windows Security Center API';Scope='Salud agregada informada por proveedores registrados; no prueba independiente de deteccion en ejecucion.'}
}
function Invoke-BoundedRead([scriptblock]$Read,[int]$Seconds=45) {
    $job=Start-Job -ScriptBlock $Read
    try {
        if(-not (Wait-Job $job -Timeout $Seconds)){throw 'Tiempo de consulta agotado; cobertura pendiente.'}
        if($job.State -ne 'Completed'){
            # Antes se descartaba el motivo real (p. ej. "El router no expone mapeos UPnP"). Ahora se informa.
            $reason=$null
            foreach($child in @($job.ChildJobs)){
                if($child.JobStateInfo.Reason){$reason=$child.JobStateInfo.Reason.Message;break}
                $err=@($child.Error)|Select-Object -First 1
                if($err){$reason=[string]$err.Exception.Message;break}
            }
            if(-not $reason){$reason='Windows no informo el motivo.'}
            throw ('La consulta no se completo: '+$reason)
        }
        Receive-Job $job -ErrorAction Stop
    } finally {Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
}
function Get-NetworkInvestigation {
    $processes=@{};foreach($p in Get-CimInstance Win32_Process -OperationTimeoutSec 15){$processes[[int]$p.ProcessId]=$p}
    # Solo escuchas reales (Get-ListeningSockets descarta PID 0/TIME_WAIT y filas que no figuran como LISTEN en .NET).
    # IPv4 e IPv6 del mismo programa/puerto se agrupan en una fila.
    $listeners=foreach($g in @(Get-ListeningSockets|Group-Object {[string]$_.OwningProcess+'|'+$_.LocalPort})){
        $l=$g.Group[0];$p=$processes[[int]$l.OwningProcess]
        $addresses=@($g.Group|ForEach-Object {[string]$_.LocalAddress}|Select-Object -Unique)
        $scopes=@($addresses|ForEach-Object {Get-ListenerScope $_})
        $scope=if($scopes -contains 'AllInterfaces'){'AllInterfaces'}elseif($scopes -contains 'SingleInterface'){'SingleInterface'}else{'Loopback'}
        $isSystemService=Test-WindowsListener $p.Name $p.ExecutablePath $l.OwningProcess
        $protected=[int]$l.LocalPort -in @(22,135,139,445,3389,5900,5938,5985,5986)
        $canBlock=($scope -ne 'Loopback' -and [int]$l.OwningProcess -gt 4 -and -not $protected -and [bool]$p.ExecutablePath -and -not $isSystemService)
        $note=if($canBlock){''}elseif($scope -eq 'Loopback'){'Solo accesible desde esta PC; no hace falta bloquear.'}elseif($isSystemService){'Servicio de Windows; bloquearlo puede romper funciones del sistema.'}elseif($protected){'Puerto de administracion remota protegido; desactivar el servicio desde su configuracion.'}elseif(-not $p.ExecutablePath){'No se pudo leer la ruta del programa (puede ser un servicio de otra cuenta). Abrir Centinela y aceptar UAC al reintentar la lectura.'}else{'Bloqueo no disponible.'}
        [pscustomobject]@{Address=($addresses -join ', ');Port=$l.LocalPort;ProcessId=$l.OwningProcess;Process=$p.Name;Executable=$p.ExecutablePath;Scope=$scope;IsWindows=$isSystemService;Risk=(Get-ListenerRisk $l.LocalPort $scope $isSystemService);CanBlock=$canBlock;BlockNote=$note}
    }
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -ErrorAction Stop)
    if($rules.Count -gt 1000){throw 'Mas de 1000 reglas; investigacion cancelada para no presentar cobertura incompleta como completa.'}
    $ruleDetails=foreach($rule in $rules){
        $ports=$rule|Get-NetFirewallPortFilter -ErrorAction Stop
        $app=$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop
        $address=$rule|Get-NetFirewallAddressFilter -ErrorAction Stop
        [pscustomobject]@{Name=$rule.Name;DisplayName=$rule.DisplayName;Action=$rule.Action;Profile=$rule.Profile;Source=$rule.PolicyStoreSourceType;Protocol=$ports.Protocol;LocalPort=$ports.LocalPort;Program=$app.Program;LocalAddress=$address.LocalAddress;RemoteAddress=$address.RemoteAddress;Enforcement=$rule.EnforcementStatus}
    }
    [pscustomobject]@{
        Listeners=@($listeners|Sort-Object @{e={if($_.Scope -eq 'Loopback'){2}elseif($_.IsWindows){1}else{0}}},Port)
        Routes=@(Get-NetRoute -ErrorAction Stop|Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')|Select-Object InterfaceAlias,NextHop,RouteMetric)
        Adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|Where-Object {$_.Status -eq 'Up'}|Select-Object Name,InterfaceDescription,Status)
        VPNProfiles=(Invoke-Check 'VPNProfiles' { @((Get-VpnConnection -ErrorAction Stop))+@((Get-VpnConnection -AllUserConnection -ErrorAction Stop))|Select-Object Name,TunnelType,ConnectionStatus,ServerAddress })
        InboundRules=@($ruleDetails)
        Note='Reglas efectivas con programa/puertos/direcciones para correlacion con escuchas; filtros de servicio/IPsec/paquetes pueden requerir revision adicional. No permite inferir accesibilidad externa. VPN de terceros se muestra como adaptador, no se clasifica por nombre.'
    }
}
function Get-RouterMappings {
    Invoke-BoundedRead {
        try{$nat=New-Object -ComObject HNetCfg.NATUPnP;$collection=$nat.StaticPortMappingCollection}
        catch{throw ('Windows no pudo consultar UPnP del router ('+$_.Exception.Message+'). Puede estar desactivada la deteccion de redes.')}
        if($null -eq $collection){
            # Caso mas comun: UPnP desactivado en el router o red marcada Publica. No es un error: se informa como dato.
            return [pscustomobject]@{UPnPAvailable=$false;Mappings=@();Scope='El router no respondio a UPnP (desactivado, no soportado o red Publica). Las redirecciones manuales solo se ven en la configuracion del router.'}
        }
        $entries=@();foreach($m in $collection){$entries+=[pscustomobject]@{ExternalPort=$m.ExternalPort;Protocol=$m.Protocol;InternalPort=$m.InternalPort;InternalClient=$m.InternalClient;Enabled=$m.Enabled;Description=$m.Description}}
        [pscustomobject]@{UPnPAvailable=$true;Mappings=$entries;Scope='Mapeos UPnP publicados; reglas manuales y administracion remota del router requieren su interfaz.'}
    }
}
function Get-PendingUpdates {
    Invoke-BoundedRead -Seconds 120 -Read {
        $session=New-Object -ComObject Microsoft.Update.Session
        $search=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        if($search.ResultCode -ne 2){throw ('Busqueda parcial/fallida: '+$search.ResultCode)}
        $updates=foreach($u in $search.Updates){[pscustomobject]@{Title=$u.Title;KB=@($u.KBArticleIDs);Severity=$u.MsrcSeverity;SecurityBulletins=@($u.SecurityBulletinIDs);UpdateId=$u.Identity.UpdateID;Security=(@($u.Categories|Where-Object CategoryID -eq '0FA1201D-4330-4FA8-8AE9-B877473B6441').Count -gt 0)}}
        [pscustomobject]@{Updates=@($updates);Source='Windows Update Agent, origen configurado en Windows';RebootRequired=(New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired;Scope='Parches aplicables ofrecidos por el origen; no inventario universal de CVE de todas las aplicaciones.'}
    }
}
function Get-OSLicensing {
    $os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $licenses=@(Get-CimInstance SoftwareLicensingProduct -Filter 'LicenseStatus=1' -OperationTimeoutSec 20|Where-Object {$_.Name -match 'ESU|Extended Security'}|Select-Object Name,Description,LicenseStatus)
    [pscustomobject]@{Caption=$os.Caption;Build=$os.BuildNumber;Edition=$version.EditionID;DisplayVersion=$version.DisplayVersion;ESULicenses=$licenses;LifecycleReference='https://learn.microsoft.com/windows/release-health/';Interpretation='Canal, edicion y licencias ESU detectadas. Una licencia encontrada no acredita por si sola cobertura vigente; contrastar periodo y parches ofrecidos.'}
}
function Get-InsiderInfo {
    $info=[pscustomobject]@{IsInsider=$false;Channel=$null}
    foreach($key in @('HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability','HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Selection')){
        $v=Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if(-not $v){continue}
        $channel=@($v.BranchName,$v.UIBranch,$v.Ring,$v.UIRing)|Where-Object {$_}|Select-Object -First 1
        if($channel -or $v.EnablePreviewBuilds -eq 2){$info.IsInsider=$true;if($channel -and -not $info.Channel){$info.Channel=[string]$channel}}
    }
    return $info
}
function Get-SupportAssessment {
    $os=Get-OSLicensing
    $insider=$null;try{$insider=Get-InsiderInfo}catch{}
    if($insider -and $insider.IsInsider){
        return [pscustomobject]@{OS=$os;Status='Insider';Source='Registro WindowsSelfHost';CheckedAt=[datetime]::UtcNow.ToString('o');EndDate=$null;Detail="Windows Insider (canal: $(if($insider.Channel){$insider.Channel}else{'no informado'}), build $($os.Build)). Las builds de prueba no figuran en el ciclo de vida oficial: reciben parches por Windows Update del programa Insider y caducan. Mantener Windows Update al dia; para maxima estabilidad usar una version publica."}
    }
    $path=if($os.Caption -match 'Windows 11' -and $os.Edition -match '^(Core|Professional)'){'windows-11-home-and-pro'}elseif($os.Caption -match 'Windows 11' -and $os.Edition -match '^(Enterprise|Education)' -and $os.Edition -notmatch 'S$'){'windows-11-enterprise-and-education'}elseif($os.Caption -match 'Windows 10' -and $os.Edition -match '^(Core|Professional)'){'windows-10-home-and-pro'}else{$null}
    if(-not $path){return [pscustomobject]@{Status='Unknown';OS=$os;Detail='Edicion/canal LTSC o no catalogado. Licencias detectadas incluidas; requiere confirmar pagina especifica de producto.'}}
    $url='https://learn.microsoft.com/en-us/lifecycle/products/'+$path
    $html=(Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop).Content
    $end=$null
    foreach($row in [regex]::Matches($html,'(?is)<tr\b[^>]*>.*?</tr>')){
        $plain=[Net.WebUtility]::HtmlDecode([regex]::Replace($row.Value,'<[^>]+>',' '))
        if($plain -notmatch [regex]::Escape('Version '+$os.DisplayVersion)){continue}
        $attributes=[regex]::Matches($row.Value,'(?i)datetime="([^"]+)"')
        if($attributes.Count -ge 2){$end=[datetime]::Parse($attributes[$attributes.Count-1].Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal);break}
        $dates=[regex]::Matches($plain,'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}\b')
        if($dates.Count -ge 2){$end=[datetime]::Parse($dates[$dates.Count-1].Value,[Globalization.CultureInfo]::InvariantCulture);break}
    }
    [pscustomobject]@{OS=$os;Source=$url;CheckedAt=[datetime]::UtcNow.ToString('o');EndDate=$end;Status=$(if($end){if([datetime]::Now -le $end){'InSupportUntil'}else{'StandardSupportEnded'}}else{'Unknown'});Detail=$(if(-not $end){"La version $($os.DisplayVersion) (build $($os.Build)) no aparece en la tabla oficial. Si es una build Insider/Canary, unirse al programa queda registrado en Configuracion > Windows Update > Programa Windows Insider. "}else{''})+'Fecha obtenida de tabla oficial para version/edicion. Si termina el soporte estandar, ESU requiere comprobar periodo/licencia aplicable; no se presupone cobertura.'}
}
function Get-CveCorrelation($Report) {
    $updates=@(Get-CheckData $Report 'Updates');if(-not $updates.Count){throw 'Consultar primero Windows Update.'}
    $kbs=@($updates[0].Updates|ForEach-Object {$_.KB}|ForEach-Object {[string]$_})
    $kbSet=New-Object 'Collections.Generic.HashSet[string]'
    foreach($kb in $kbs){$kbSet.Add($kb)|Out-Null}
    $found=New-Object 'Collections.Generic.List[object]';$sources=@();$gaps=@()
    for($i=0;$i -lt 3;$i++){
        $month=[datetime]::UtcNow.AddMonths(-$i).ToString('yyyy-MMM',[Globalization.CultureInfo]::InvariantCulture)
        $url='https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/'+$month
        try{
            $response=Invoke-WebRequest -Uri $url -Headers @{Accept='application/json'} -UseBasicParsing -TimeoutSec 45 -ErrorAction Stop
            if($response.RawContentLength -gt 64MB){throw 'Documento excede limite de 64 MiB.'}
            $doc=$response.Content|ConvertFrom-Json;$sources+=$url
            foreach($v in $doc.Vulnerability){foreach($fix in $v.Remediations){foreach($article in [regex]::Matches([string]$fix.Description.Value,'(?<!\d)\d{6,8}(?!\d)')){
                $kb=$article.Value
                if($kbSet.Contains($kb)){
                    $found.Add([pscustomobject]@{CVE=$v.CVE;Title=$v.Title.Value;KB=$kb;Source=$url})
                }
            }}}
        }catch{
            # El boletin del mes en curso no existe hasta el segundo martes: no es una falta de cobertura.
            if($i -eq 0 -and $_.Exception.Message -match '404|Not Found|no encontr'){continue}
            $gaps+=($url+': '+$_.Exception.Message)
        }
    }
    [pscustomobject]@{Matches=@($found.ToArray()|Sort-Object CVE,KB -Unique);Sources=$sources;Gaps=$gaps;Scope='Correlacion KB pendientes con CVRF Microsoft de los ultimos 3 meses. No cubre software tercero ni prueba explotabilidad; cero coincidencias no acredita ausencia de CVE.'}
}
function Block-VerifiedListener([int]$Port,[int]$ProcessId,[string]$ExpectedProgram) {
    if(-not (Test-IsAdmin)){throw 'Requiere administrador para crear una regla de firewall.'}
    if($ProcessId -le 4 -or $Port -lt 1 -or $Port -gt 65535 -or $Port -in @(22,135,139,445,3389,5900,5938,5985,5986)){throw 'Servicio del sistema/administracion protegido; requiere evaluacion especifica.'}
    $p=Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -OperationTimeoutSec 15
    if(-not $p.ExecutablePath -or $p.ExecutablePath -ne $ExpectedProgram){throw 'El proceso o su ejecutable cambiaron; repetir investigacion.'}
    Test-LocalPath $p.ExecutablePath|Out-Null
    if($p.ExecutablePath.StartsWith($env:SystemRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Ejecutable de Windows protegido; requiere revision especifica.'}
    $listeners=@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop|Where-Object OwningProcess -eq $ProcessId)
    if(-not $listeners.Count){throw 'La escucha ya cambio; repetir investigacion.'}
    $name='Centinela-'+[guid]::NewGuid().ToString('N')
    $record=[pscustomobject]@{Action='BlockListener';Status='Pending';Rule=$name;Port=$Port;Program=$p.ExecutablePath;Detail='Pendiente de aplicar.'}
    $recordPath=Join-Path (Get-StateFolder) ('firewall-'+[guid]::NewGuid().ToString('N')+'.json')
    Save-Journal $record $recordPath
    New-NetFirewallRule -Name $name -DisplayName "Centinela: bloquear TCP $Port ($($p.Name))" -Direction Inbound -Action Block -Protocol TCP -LocalPort $Port -Program $p.ExecutablePath -Profile Any -ErrorAction Stop|Out-Null
    $rule=Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
    if([string]$rule.Enabled -ne 'True' -or [string]$rule.Action -ne 'Block'){throw "Regla creada pero efecto no verificado: $name"}
    $record.Status='RuleVerified';$record.Detail='Regla de bloqueo presente en ActiveStore. El proceso puede seguir escuchando: se bloquea trafico entrante, no se mata la aplicacion. Alcanzabilidad externa pendiente de prueba independiente.'
    Save-Journal $record $recordPath
    return $record
}
function Undo-ListenerBlock([string]$Name) {
    if($Name -notmatch '^Centinela-[a-f0-9]{32}$'){throw 'Identificador no permitido.'}
    Remove-NetFirewallRule -Name $Name -ErrorAction Stop
    if(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue){throw 'La regla sigue presente.'}
}
function Write-NetworkTable($Network) {
    $rows=@($Network.Listeners|Where-Object {$_.Scope -ne 'Loopback' -and -not $_.IsWindows})
    $windows=@($Network.Listeners|Where-Object {$_.Scope -ne 'Loopback' -and $_.IsWindows})
    $local=@($Network.Listeners|Where-Object Scope -eq 'Loopback')
    if($rows.Count){
        Write-Host ''
        Write-Host 'Programas que aceptan conexiones desde otros equipos:'
        Write-Host ('  {0,-3} {1,-24} {2,-7} {3,-22} {4}' -f 'N','Programa','Puerto','Abierto en','Comentario')
        for($i=0;$i -lt $rows.Count;$i++){
            $r=$rows[$i];$where=if($r.Scope -eq 'AllInterfaces'){'todas las redes'}else{'solo '+$r.Address}
            $name=if($r.Process){[string]$r.Process}else{'PID '+$r.ProcessId}
            if($name.Length -gt 24){$name=$name.Substring(0,23)+'~'}
            $flag=if($r.Risk.Level -in @('Alert','Review')){'[!] '}else{''}
            Write-Host ('  {0,-3} {1,-24} {2,-7} {3,-22} {4}{5}' -f ($i+1),$name,$r.Port,$where,$flag,$r.Risk.Text)
        }
    } else {Write-Host 'Ningun programa (fuera de Windows) acepta conexiones desde la red.'}
    if($windows.Count){Write-Host ('Servicios de Windows abiertos a la red (normales): '+(($windows|ForEach-Object {"$($_.Process) $($_.Port)"}) -join ', '))}
    if($local.Count){Write-Host "$($local.Count) escuchas solo locales (127.0.0.1/::1): no son accesibles desde otros equipos."}
    $gw=@($Network.Routes|ForEach-Object {"$($_.NextHop) ($($_.InterfaceAlias))"})
    if($gw.Count){Write-Host ('Salida a Internet por: '+($gw -join ', '))}
    return $rows
}
function Show-NetworkInvestigation {
    try{$network=Get-NetworkInvestigation}catch{
        Write-Warning $_.Exception.Message
        if(-not (Confirm-Choice 'Reintentar lectura de red con permisos de administrador, sin cambiar reglas?')){throw 'Investigacion cancelada o pendiente por permisos.'}
        $read=Invoke-ElevatedSecurity 'NetworkRead' @{}
        if($read.Status -ne 'Checked'){throw $read.Detail};$network=$read.Data
    }
    $rows=@(Write-NetworkTable $network)
    if(-not @($rows|Where-Object CanBlock).Count){return $network}
    Write-Host 'Bloquear crea una regla de firewall reversible (opcion 8 > 5 la quita). Puede afectar juegos, compartir archivos o la app elegida.'
    $answer=Read-Host "Numero de fila (N, 1 a $($rows.Count)) a bloquear. Enter = solo mirar"
    if(-not $answer -or -not $answer.Trim()){return $network}
    $n=0
    # Se acepta el numero de fila. Si escribe un puerto que aparece en la tabla, se usa esa fila (el error anterior "escucha unica" confundia).
    if([int]::TryParse($answer.Trim().TrimStart('#'),[ref]$n)){
        $byPort=@($rows|Where-Object {[int]$_.Port -eq $n})
        if($n -ge 1 -and $n -le $rows.Count){$entry=$rows[$n-1]}
        elseif($byPort.Count -eq 1){$entry=$byPort[0]}
        else{$entry=$null}
    } else {$entry=$null}
    if(-not $entry){Write-Warning "Escribir el numero de la columna N (1 a $($rows.Count)), no otro dato. No se cambio nada.";return $network}
    if(-not $entry.CanBlock){Write-Warning ("No se ofrece bloqueo para $($entry.Process) puerto $($entry.Port): "+$entry.BlockNote);return $network}
    Write-Host "$($entry.Process) - $($entry.Executable) - TCP $($entry.Port)"
    if(Confirm-Choice 'Crear regla reversible de bloqueo entrante?'){
        try{$result=Invoke-ElevatedSecurity 'BlockListener' @{Port=[int]$entry.Port;ProcessId=[int]$entry.ProcessId;Program=$entry.Executable}}
        catch{$result=[pscustomobject]@{Action='BlockListener';Status='Failed';Detail=$_.Exception.Message}}
        $network|Add-Member -MemberType NoteProperty -Name ActionResult -Value $result -Force
        Write-Host ("Resultado: $($result.Status). $($result.Detail)")
    }
    return $network
}
function Format-DeepResult($Id,$Result) {
    if($Result.Status -ne 'Checked'){Write-Warning ((Get-CheckTitle $Id)+': '+$Result.Error);Write-Host ('  '+(Get-FailureAdvice $Id $Result.Error));return}
    $d=@($Result.Data)|Select-Object -Last 1
    switch($Id){
        'NetworkInvestigation' {} # ya se mostro la tabla legible
        'Router' {
            if(-not $d.UPnPAvailable){Write-Host 'Router: no responde a UPnP. Los programas no pueden abrir puertos en el router por su cuenta (bien).'}
            elseif(-not @($d.Mappings).Count){Write-Host 'Router: UPnP activo, sin puertos abiertos automaticamente ahora.'}
            else{Write-Host 'Router: puertos abiertos hacia Internet por UPnP:';foreach($m in $d.Mappings){Write-Host ("  Internet:{0}/{1} -> {2}:{3}  {4}{5}" -f $m.ExternalPort,$m.Protocol,$m.InternalClient,$m.InternalPort,$m.Description,$(if($m.Enabled){''}else{' (deshabilitado)'}))}}
        }
        'Updates' {
            $sec=@($d.Updates|Where-Object Security -eq $true)
            Write-Host "Windows Update: $(@($d.Updates).Count) parches pendientes, $($sec.Count) de seguridad. Reinicio pendiente: $(if($d.RebootRequired){'si'}else{'no'})."
            foreach($u in $d.Updates){Write-Host ('  - '+$u.Title)}
            if($sec.Count){Write-Host '  Instalar con opcion 8 > 7 o desde Configuracion > Windows Update.'}
        }
        'Support' {Write-Host ("Soporte: $($d.Status). "+$(if($d.EndDate){"Fin: $($d.EndDate). "}else{''})+$d.Detail)}
        'CVE' {
            Write-Host "CVE: $(@($d.Matches).Count) vulnerabilidades Microsoft corregidas por parches que te faltan."
            foreach($m in @($d.Matches|Select-Object -First 10)){Write-Host "  $($m.CVE) (KB$($m.KB)) $($m.Title)"}
            if(@($d.Gaps).Count){Write-Warning ('Fuentes no consultadas: '+($d.Gaps -join '; '))}
        }
        'IOC' {Write-Host ("IOC: codigo $($d.ExitCode). "+($d.Verdict|ConvertTo-Json -Compress -Depth 3)+" Informe: $($d.EvidenceReport)")}
        default {$d|Format-List|Out-Host}
    }
}
function Add-DeepResult($Report,$Id,[scriptblock]$Read) {
    $result=Invoke-Check $Id $Read
    if($Id -eq 'PublicProbe'){ $prior=@($Report.Checks|Where-Object Id -eq $Id|ForEach-Object {$_.Data});$result.Data=@((@($prior)+@($result.Data))|Select-Object -Last 50) }
    $Report.Checks=@($Report.Checks|Where-Object Id -ne $Id)+@($result)
    Add-ReportAnalysis $Report|Out-Null
    Format-DeepResult $Id $result
}
function Show-DeepMenu($Report) {
    Write-Host '[1] Procesos, puertos, VPN y firewall / bloqueo reversible'
    Write-Host '[2] Consultar mapeos publicados por el router (UPnP)'
    Write-Host '[3] Buscar parches aplicables con Windows Update (online)'
    Write-Host '[4] Soporte oficial online, edicion/canal y licencias ESU/LTSC'
    Write-Host '[5] Deshacer un bloqueo de puerto creado por Centinela'
    Write-Host '[6] Analisis IOC Zero-Breach con aislamiento de Python'
    Write-Host '[7] Instalar parches de seguridad previamente consultados'
    Write-Host '[8] Importar prueba ejecutada desde otra red'
    Write-Host '[9] Correlacion CVE/KB con Microsoft MSRC (online)'
    Write-Host '[10] Prueba externa voluntaria sin servidor propio (Globalping)'
    $choice=Read-Host 'Comprobacion (Enter vuelve)'
    switch($choice){
        '1' {Add-DeepResult $Report 'NetworkInvestigation' {Show-NetworkInvestigation}}
        '2' {if(Confirm-Choice 'Consultar al router local sin modificar sus reglas?'){Add-DeepResult $Report 'Router' {Get-RouterMappings}}}
        '3' {if(Confirm-Choice 'Consultar Windows Update por red? No instala ni reinicia.'){Add-DeepResult $Report 'Updates' {Get-PendingUpdates}}}
        '4' {if(Confirm-Choice 'Consultar tabla oficial de soporte por Internet?'){Add-DeepResult $Report 'Support' {Get-SupportAssessment}}}
        '9' {if(Confirm-Choice 'Consultar CVRF Microsoft de los ultimos 3 meses?'){Add-DeepResult $Report 'CVE' {Get-CveCorrelation $Report}}}
        '10' {
            Write-Host 'IPify recibira la consulta de IP publica; Globalping recibira esa IP y el puerto, y puede conservar/publicar el reporte. No envia inventarios ni informes de la PC.'
            $portText=Read-Host 'Un puerto TCP propio a comprobar';$port=0
            $family=Read-Host 'Familia de salida a comprobar: 4 (IPv4) o 6 (IPv6)'
            if([int]::TryParse($portText,[ref]$port) -and $port -ge 1 -and $port -le 65535 -and $family -in @('4','6') -and (Confirm-Choice 'Consultar servicios externos para esta prueba?')){
                Add-DeepResult $Report 'PublicProbe' {Get-PublicProbe $port $family}
            }
        }
        '6' {Write-Host 'Lee artefactos privados locales y guarda resultados. UAC crea un bloqueo saliente temporal para Python y vuelve a pedir permiso para retirarlo. Si se interrumpe, revisar reglas Centinela-IOC en Firewall.';if(Confirm-Choice 'Ejecutar analisis IOC?'){Add-DeepResult $Report 'IOC' {Invoke-IocScan}}}
        '7' {
            $updates=@(Get-CheckData $Report 'Updates')
            if(-not $updates.Count){throw 'Primero consultar parches (opcion 3).'}
            $security=@($updates[0].Updates|Where-Object Security -eq $true)
            $security|Format-Table Title,KB|Out-Host
            if($security.Count -and (Confirm-Choice 'Descargar e instalar SOLO estos parches de seguridad, aceptar sus EULA y dejar reinicio pendiente si hace falta?')){
                $result=Invoke-ElevatedSecurity 'InstallSecurityUpdates' @{Ids=@($security.UpdateId)}
                if(-not $Report.PSObject.Properties['ActionHistory']){$Report|Add-Member -MemberType NoteProperty -Name ActionHistory -Value @()}
                $Report.ActionHistory=@($Report.ActionHistory)+@($result)
                $result|Format-List|Out-Host
                Add-DeepResult $Report 'Updates' {Get-PendingUpdates}
            }
        }
        '8' {
            Write-Host 'Ejecutar tools/ExternalProbe.ps1 desde una PC fuera de tu red contra TU IP publica y puertos autorizados. No probar desde la misma red/VPN.'
            $path=Read-Host 'Ruta JSON de la prueba externa (Enter cancela)'
            if($path){Add-DeepResult $Report 'ExternalProbe' {Import-ExternalProbe $path}}
        }
        '5' {
            $files=@(Get-ChildItem -LiteralPath (Get-StateFolder) -Filter 'firewall-*.json' -File)
            for($i=0;$i -lt $files.Count;$i++){Write-Host "[$i] $($files[$i].Name)"}
            $answer=Read-Host 'Numero de registro';$index=0
            if([int]::TryParse($answer,[ref]$index) -and $index -ge 0 -and $index -lt $files.Count -and (Confirm-Choice 'Eliminar solo la regla seleccionada?')){
                $record=Get-Content -LiteralPath $files[$index].FullName -Raw|ConvertFrom-Json
                Invoke-ElevatedSecurity 'UndoBlock' @{Rule=$record.Rule}|Format-List|Out-Host
            }
        }
    }
}
function Get-PublicProbe([int]$Port,[ValidateSet('4','6')][string]$Family='4') {
    if($Port -lt 1 -or $Port -gt 65535){throw 'Puerto invalido.'}
    $lookup=if($Family -eq '6'){'https://api6.ipify.org?format=json'}else{'https://api.ipify.org?format=json'}
    $observed=Invoke-RestMethod -Uri $lookup -TimeoutSec 15 -ErrorAction Stop
    $ip=$null
    if(-not [Net.IPAddress]::TryParse([string]$observed.ip,[ref]$ip)){throw 'IP publica no verificable.'}
    $b=$ip.GetAddressBytes()
    if([Net.IPAddress]::IsLoopback($ip) -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast){throw 'Se requiere una IP publica.'}
    if($b.Length -eq 4 -and ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127))){throw 'IP privada/compartida no valida para la prueba publica.'}
    if($b.Length -eq 16 -and (($b[0] -band 254) -eq 252 -or $ip.IsIPv4MappedToIPv6)){throw 'Direccion IPv6 no global o mapeada; elegir la familia correcta.'}
    Write-Host "La IP de salida observada es $ip; se comprobara TCP $Port desde un nodo externo."
    if(-not (Confirm-Choice 'Confirmas que controlas/autorizas esa IP y que no es una salida VPN/corporativa/compartida ajena?')){throw 'Prueba externa cancelada antes de enviar el objetivo a Globalping.'}
    $body=@{type='ping';target=$ip.ToString();limit=1;measurementOptions=@{protocol='TCP';port=$Port;packets=1}}|ConvertTo-Json -Depth 5 -Compress
    $request=Invoke-RestMethod -Uri 'https://api.globalping.io/v1/measurements' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 20 -ErrorAction Stop
    if([string]$request.id -notmatch '^[A-Za-z0-9]{1,64}$' -or $request.probesCount -ne 1){throw 'El proveedor no devolvio una solicitud verificable.'}
    $status='Pending';$nodes=@()
    for($attempt=0;$attempt -lt 5;$attempt++){
        $response=Invoke-RestMethod -Uri ('https://api.globalping.io/v1/measurements/'+$request.id) -TimeoutSec 12 -ErrorAction Stop
        if($response.status -eq 'finished'){
            $status='Unknown';$nodes=@($response.results)
            if($response.id -eq $request.id -and $response.type -eq 'ping' -and $response.target -eq $ip.ToString() -and $response.measurementOptions.protocol -eq 'TCP' -and $response.measurementOptions.port -eq $Port -and $nodes.Count -eq 1){
                $detail=$nodes[0].result;$answer=$null
                if($detail.status -eq 'finished' -and [Net.IPAddress]::TryParse([string]$detail.resolvedAddress,[ref]$answer) -and $answer.Equals($ip)){
                    $validRtt=@($detail.timings|Where-Object { ($_.rtt -is [int] -or $_.rtt -is [long] -or $_.rtt -is [double] -or $_.rtt -is [decimal]) -and $_.rtt -ge 0 -and -not [double]::IsNaN([double]$_.rtt) -and -not [double]::IsInfinity([double]$_.rtt) })
                    if(($detail.stats.rcv -is [int] -or $detail.stats.rcv -is [long]) -and $detail.stats.rcv -gt 0 -and $validRtt.Count){$status='Reachable'}
                    elseif(($detail.stats.total -is [int] -or $detail.stats.total -is [long]) -and $detail.stats.total -gt 0 -and $detail.stats.rcv -eq 0){$status='NoConnection'}
                }
            }
            break
        }
        Start-Sleep -Seconds 1
    }
    [pscustomobject]@{Provider='Globalping';Target=$ip.ToString();Family=$Family;Port=$Port;Status=$status;At=[datetime]::UtcNow.ToString('o');RequestId=$request.id;EvidenceLink=('https://api.globalping.io/v1/measurements/'+$request.id);Nodes=$nodes;Scope='Un nodo externo, una IP/familia/puerto y fecha. Puede ser router/VPN/NAT u otro dispositivo; correlacionar con red local. NoConnection/Unknown/Pending no acreditan seguridad.'}
}

function Get-KnownPython {
    $base=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\Python'
    if(Test-Path -LiteralPath $base){foreach($d in Get-ChildItem -LiteralPath $base -Directory|Sort-Object Name -Descending){
        $exe=Join-Path $d.FullName 'python.exe'
        if(Test-Path -LiteralPath $exe){Test-LocalPath $exe|Out-Null;return $exe}
    }}
    throw 'Python no detectado en Programs/Python de esta cuenta. Instalar Python oficial para usar el motor IOC; no se instala automaticamente.'
}
function Read-IocReport([string]$Path) {
    if((Get-Item -LiteralPath $Path).Length -gt 32MB){throw 'Informe IOC demasiado grande.'}
    $doc=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
    if($doc.schema_version -ne '1.6' -or $doc.exit_code -notin @(0,1,2,3,4)){throw 'Contrato IOC no soportado; no se infiere un resultado limpio.'}
    [pscustomobject]@{Engine='Zero-Breach-Toolkit';Schema=$doc.schema_version;ExitCode=$doc.exit_code;Verdict=$doc.verdict;Coverage=$doc.coverage;Caveats=$doc.must_relay;NextSteps=$doc.next_steps;EvidenceReport=$Path;Warning='Sin coincidencias no equivale a ausencia de compromiso. No borrar evidencia automaticamente.'}
}
function Invoke-IocScan {
    # La logica es correcta: si el proceso tiene token de administrador, no se lanza Python de usuario elevado.
    # El fallo real era el mensaje: no explicaba POR QUE el menu estaba elevado (UAC desactivado o consola de administrador).
    if(Test-IsAdmin){throw ('El analisis IOC no se ejecuta con permisos de administrador (seria correr Python de esta cuenta con control total). '+(Get-ElevationExplanation))}
    $exe=Get-KnownPython
    $scanner=Join-Path (Split-Path $PSScriptRoot -Parent) 'third_party\zero-breach\scanner.py'
    if((Get-FileHash -LiteralPath $scanner -Algorithm SHA256).Hash -ne 'BB0E6A7A36EE659C0494D02E9F7495D5FD4701F1AB7E57529E79925CB581AE15'){throw 'Motor IOC alterado; se rechaza su ejecucion.'}
    $folder=Get-StateFolder;$id=[guid]::NewGuid().ToString('N');$json=Join-Path $folder ('ioc-'+$id+'.json');$txt=Join-Path $folder ('ioc-'+$id+'.txt')
    $rule=$null
    try {
        $isolation=Invoke-ElevatedSecurity 'IsolatePython' @{}
        if($isolation.Status -ne 'Verified'){throw 'Aislamiento de red no verificado. No se ejecuta el analisis IOC.'}
        $rule=$isolation.Rule
        & $exe -I -S -X utf8 $scanner --no-menu --json $json --report $txt
        $code=$LASTEXITCODE
        if($code -notin @(0,2,3) -or -not (Test-Path -LiteralPath $json)){throw "Analisis incompleto/error de ejecucion ($code). Revisar archivos guardados en $folder"}
        $result=Read-IocReport $json
        if($result.ExitCode -ne $code){throw 'El exit code y el informe no concuerdan.'}
        return $result
    } finally {
        if($rule){Invoke-ElevatedSecurity 'UndoIsolation' @{Rule=$rule}|Out-Host}
    }
}
$script:WorkerFiles=@('SecurityWorker.ps1','Centinela.ps1','Summary.ps1','DeepSecurity.ps1')
$script:WorkerBootstrap=@'
$ErrorActionPreference='Stop'
$src='__SRC__';$id='__ID__';$payload='__PAYLOAD__';$manifest=[ordered]@{__MANIFEST__}
$sha=[Security.Cryptography.SHA256]::Create();$files=@{}
foreach($name in $manifest.Keys){
    $bytes=[IO.File]::ReadAllBytes((Join-Path $src $name))
    if((-join($sha.ComputeHash($bytes)|ForEach-Object {$_.ToString('X2')})) -ne $manifest[$name]){throw "Archivo alterado antes de elevar: $name. No se ejecuto nada."}
    $files[$name]=$bytes
}
$sys='S-1-5-18';$adm='S-1-5-32-544'
function Lock-CentinelaFolder([string]$Path){
    if(Test-Path -LiteralPath $Path){$i=Get-Item -LiteralPath $Path -Force;if(-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Carpeta protegida invalida: $Path"}}else{New-Item -ItemType Directory -Path $Path|Out-Null}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier $adm));$acl.SetAccessRuleProtection($true,$false)
    $inh=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit';$none=[Security.AccessControl.PropagationFlags]::None
    foreach($s in @($sys,$adm)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $s),'FullControl',$inh,$none,'Allow')))}
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'),'ReadAndExecute',$inh,$none,'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$root=Join-Path $env:ProgramData 'Centinela'
if(Test-Path -LiteralPath $root){if((Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @($sys,$adm)){Remove-Item -LiteralPath $root -Recurse -Force}}
Lock-CentinelaFolder $root;$base=Join-Path $root 'worker';Lock-CentinelaFolder $base
Get-ChildItem -LiteralPath $base -Directory|Where-Object {$_.LastWriteTime -lt (Get-Date).AddHours(-1)}|Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
$dst=Join-Path $base $id;New-Item -ItemType Directory -Path $dst|Out-Null
foreach($name in $files.Keys){[IO.File]::WriteAllBytes((Join-Path $dst $name),$files[$name])}
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& (Join-Path $dst 'SecurityWorker.ps1') -Payload $payload
'@
function Get-WorkerManifest([string]$Folder=$PSScriptRoot) {
    $m=[ordered]@{}
    foreach($f in $script:WorkerFiles){$m[$f]=(Get-FileHash -LiteralPath (Join-Path $Folder $f) -Algorithm SHA256).Hash.ToUpperInvariant()}
    return $m
}
function New-WorkerBootstrap([string]$Source,[string]$Id,[string]$Payload,$Manifest) {
    if($Id -notmatch '^[a-f0-9]{32}$' -or $Payload -notmatch '^[A-Za-z0-9+/=]+$'){throw 'Solicitud invalida.'}
    $pairs=foreach($k in $Manifest.Keys){if($k -notin $script:WorkerFiles -or $Manifest[$k] -notmatch '^[A-F0-9]{64}$'){throw 'Manifiesto invalido.'};"'$k'='$($Manifest[$k])'"}
    return $script:WorkerBootstrap.Replace('__SRC__',$Source.Replace("'","''")).Replace('__ID__',$Id).Replace('__PAYLOAD__',$Payload).Replace('__MANIFEST__',($pairs -join ';'))
}
function Get-WorkerResultPath([string]$Id) { Join-Path (Join-Path (Join-Path (Join-Path $env:ProgramData 'Centinela') 'worker') $Id) 'result.json' }
function Read-WorkerResult([string]$Path,[string]$Id,[string]$Action,[int]$MaxBytes=2MB) {
    # Solo datos: tamano acotado, JSON, esquema/Id/Accion exactos. Nunca se ejecuta nada del archivo.
    $base=[IO.Path]::GetFullPath((Join-Path (Join-Path $env:ProgramData 'Centinela') 'worker'))
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($base+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Resultado fuera de la carpeta protegida.'}
    if(-not (Test-Path -LiteralPath $full -PathType Leaf)){throw 'Sin resultado verificable de la operacion elevada.'}
    $item=Get-Item -LiteralPath $full -Force
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Resultado con enlace no permitido.'}
    if($item.Length -gt $MaxBytes -or $item.Length -eq 0){throw 'Resultado con tamano invalido.'}
    if(Get-Command Get-Acl -ErrorAction SilentlyContinue){
        $owner=(Get-Acl -LiteralPath $full).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($owner -notin @('S-1-5-18','S-1-5-32-544') -and $owner -ne (Get-Identity)){throw 'Resultado con propietario no confiable.'}
    }
    try{$doc=[IO.File]::ReadAllText($full)|ConvertFrom-Json}catch{throw 'Resultado ilegible (JSON invalido).'}
    if($doc -isnot [pscustomobject] -or $doc.Schema -ne 'Centinela.WorkerResult.1' -or $doc.Id -ne $Id -or $doc.Action -ne $Action -or $doc.Result -isnot [pscustomobject] -or $doc.Result.Status -isnot [string] -or $doc.Result.Status -notmatch '^[A-Za-z]{1,40}$'){throw 'Resultado con formato inesperado; se descarta.'}
    return $doc.Result
}
function Invoke-ElevatedSecurity([string]$Action,$Arguments) {
    if($Action -notin @('BlockListener','UndoBlock','IsolatePython','UndoIsolation','InstallSecurityUpdates','EnableRealtime','UpdateSignatures','QuickScan','NetworkRead')){throw 'Accion privilegiada no permitida.'}
    $id=[guid]::NewGuid().ToString('N');$manifest=Get-WorkerManifest $PSScriptRoot
    $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{Action=$Action;Arguments=$Arguments;Sid=(Get-Identity);Id=$id;Manifest=$manifest}|ConvertTo-Json -Compress)))
    $bootstrap=New-WorkerBootstrap $PSScriptRoot $id $payload $manifest
    if(Test-IsAdmin){& ([scriptblock]::Create($bootstrap))}else{
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
        if($encoded.Length -gt 30000){throw 'Solicitud demasiado grande para elevar.'}
        $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        # Sin -File ni -ExecutionPolicy Bypass sobre la carpeta del usuario: el bloque verifica hashes, copia a ProgramData protegido y corre desde ahi.
        $child=Start-Process -FilePath $ps -Verb RunAs -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -PassThru -Wait
        if($child.ExitCode -ne 0){throw 'La operacion elevada fallo, fue cancelada o detecto archivos alterados.'}
    }
    Read-WorkerResult (Get-WorkerResultPath $id) $id $Action
}
function Install-SelectedSecurityUpdates($Ids) {
    $approved=@($Ids)
    if(-not $approved.Count -or $approved.Count -gt 100 -or @($approved|Where-Object {$_ -notmatch '^[a-fA-F0-9-]{36}$'}).Count){throw 'Lista de parches invalida.'}
    if((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired){throw 'Reiniciar Windows antes de instalar nuevos parches.'}
    $session=New-Object -ComObject Microsoft.Update.Session
    $search=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if($search.ResultCode -ne 2){throw 'Busqueda no completa; no se instala.'}
    $collection=New-Object -ComObject Microsoft.Update.UpdateColl
    foreach($u in $search.Updates){
        if($approved -contains $u.Identity.UpdateID -and @($u.Categories|Where-Object CategoryID -eq '0FA1201D-4330-4FA8-8AE9-B877473B6441').Count){
            if(-not $u.EulaAccepted){$u.AcceptEula()};$collection.Add($u)|Out-Null
        }
    }
    if($collection.Count -ne $approved.Count){throw 'La lista cambio desde la confirmacion. Repetir consulta.'}
    $downloader=$session.CreateUpdateDownloader();$downloader.Updates=$collection;$download=$downloader.Download()
    if($download.ResultCode -ne 2){throw 'Descarga parcial/fallida; no se inicia instalacion.'}
    $installer=$session.CreateUpdateInstaller();$installer.Updates=$collection
    $result=$installer.Install()
    [pscustomobject]@{Action='InstallSecurityUpdates';Status=$(if($result.ResultCode -eq 2){'InstalledPendingVerification'}else{'PartialOrFailed'});ResultCode=$result.ResultCode;RebootRequired=$result.RebootRequired;Ids=$approved;Detail='No reinicia automaticamente. El menu vuelve a consultar aplicabilidad; reiniciar manualmente si se requiere.'}
}
function Import-ExternalProbe([string]$Path) {
    Test-LocalPath ([IO.Path]::GetFullPath($Path))|Out-Null
    if((Get-Item -LiteralPath $Path).Length -gt 1MB){throw 'Informe demasiado grande.'}
    $doc=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
    $address=$null
    if($doc.Schema -ne 'Centinela.ExternalProbe.1' -or -not [Net.IPAddress]::TryParse([string]$doc.Target,[ref]$address) -or $doc.ConfirmedExternal -isnot [bool] -or $doc.ConfirmedExternal -ne $true -or @($doc.Results).Count -gt 50){throw 'Prueba no valida o sin confirmacion de origen externo.'}
    $at=Convert-ObservedDate $doc.At
    if($at.Year -lt 2001 -or $at.ToUniversalTime() -gt [datetime]::UtcNow.AddDays(1)){throw 'Fecha externa no verificable.'}
    foreach($r in $doc.Results){if(($r.Port -isnot [int] -and $r.Port -isnot [long]) -or $r.Port -lt 1 -or $r.Port -gt 65535 -or $r.Status -notin @('Reachable','NoConnection','Error')){throw 'Resultado externo invalido.'}}
    [pscustomobject]@{Target=$doc.Target;At=$doc.At;Results=$doc.Results;Provenance='Importado: origen externo declarado por quien ejecuto la prueba, no autenticado por Centinela';Scope='Solo IP/puertos/fecha probados. No confirma que la IP corresponda actualmente a este router, ni comprueba todos los protocolos.'}
}
