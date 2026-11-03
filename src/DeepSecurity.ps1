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
        if($job.State -ne 'Completed'){throw 'La consulta no se completo.'}
        Receive-Job $job -ErrorAction Stop
    } finally {Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
}
function Get-NetworkInvestigation {
    $processes=@{};foreach($p in Get-CimInstance Win32_Process -OperationTimeoutSec 15){$processes[[int]$p.ProcessId]=$p}
    $listeners=foreach($l in Get-NetTCPConnection -State Listen -ErrorAction Stop){
        $p=$processes[[int]$l.OwningProcess]
        [pscustomobject]@{Address=$l.LocalAddress;Port=$l.LocalPort;ProcessId=$l.OwningProcess;Process=$p.Name;Executable=$p.ExecutablePath;Scope=$(if($l.LocalAddress -eq '::1' -or $l.LocalAddress -match '^127\.'){ 'Loopback' }else{'Network'});CanBlock=($l.OwningProcess -gt 4 -and $l.LocalPort -notin @(135,139,445,3389,5985,5986) -and [bool]$p.ExecutablePath)}
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
        Listeners=@($listeners)
        Routes=@(Get-NetRoute -ErrorAction Stop|Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')|Select-Object InterfaceAlias,NextHop,RouteMetric)
        VPN=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|Where-Object {$_.Status -eq 'Up'}|Select-Object Name,InterfaceDescription,Status)
        InboundRules=@($ruleDetails)
        Note='Reglas efectivas con programa/puertos/direcciones para correlacion con escuchas; filtros de servicio/IPsec/paquetes pueden requerir revision adicional. No permite inferir accesibilidad externa. VPN de terceros se muestra como adaptador, no se clasifica por nombre.'
    }
}
function Get-RouterMappings {
    Invoke-BoundedRead {
        $nat=New-Object -ComObject HNetCfg.NATUPnP
        $collection=$nat.StaticPortMappingCollection
        if($null -eq $collection){throw 'El router no expone mapeos UPnP a esta cuenta. No equivale a ausencia de redirecciones.'}
        $entries=@();foreach($m in $collection){$entries+=[pscustomobject]@{ExternalPort=$m.ExternalPort;Protocol=$m.Protocol;InternalPort=$m.InternalPort;InternalClient=$m.InternalClient;Enabled=$m.Enabled;Description=$m.Description}}
        [pscustomobject]@{Mappings=$entries;Scope='Mapeos UPnP publicados; reglas manuales y administracion remota del router requieren su interfaz.'}
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
function Get-SupportAssessment {
    $os=Get-OSLicensing
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
    [pscustomobject]@{OS=$os;Source=$url;CheckedAt=[datetime]::UtcNow.ToString('o');EndDate=$end;Status=$(if($end){if([datetime]::Now -le $end){'InSupportUntil'}else{'StandardSupportEnded'}}else{'Unknown'});Detail='Fecha obtenida de tabla oficial para version/edicion. Si termina el soporte estandar, ESU requiere comprobar periodo/licencia aplicable; no se presupone cobertura.'}
}
function Get-CveCorrelation($Report) {
    $updates=@(Get-CheckData $Report 'Updates');if(-not $updates.Count){throw 'Consultar primero Windows Update.'}
    $kbs=@($updates[0].Updates|ForEach-Object {$_.KB}|ForEach-Object {[string]$_})
    $kbSet=New-Object 'Collections.Generic.HashSet[string]'
    foreach($kb in $kbs){$kbSet.Add($kb)|Out-Null}
    $matches=New-Object 'Collections.Generic.List[object]';$sources=@();$gaps=@()
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
                    $matches.Add([pscustomobject]@{CVE=$v.CVE;Title=$v.Title.Value;KB=$kb;Source=$url})
                }
            }}}
        }catch{$gaps+=($url+': '+$_.Exception.Message)}
    }
    [pscustomobject]@{Matches=@($matches.ToArray()|Sort-Object CVE,KB -Unique);Sources=$sources;Gaps=$gaps;Scope='Correlacion KB pendientes con CVRF Microsoft de los ultimos 3 meses. No cubre software tercero ni prueba explotabilidad; cero coincidencias no acredita ausencia de CVE.'}
}
function Block-VerifiedListener([int]$Port,[int]$ProcessId,[string]$ExpectedProgram) {
    if(-not (Test-IsAdmin)){throw 'Requiere administrador para crear una regla de firewall.'}
    if($ProcessId -le 4 -or $Port -lt 1 -or $Port -gt 65535 -or $Port -in @(135,139,445,3389,5985,5986)){throw 'Servicio del sistema/administracion protegido; requiere evaluacion especifica.'}
    $p=Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -OperationTimeoutSec 15
    if(-not $p.ExecutablePath -or $p.ExecutablePath -ne $ExpectedProgram){throw 'El proceso o su ejecutable cambiaron; repetir investigacion.'}
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
function Show-NetworkInvestigation {
    try{$network=Get-NetworkInvestigation}catch{
        Write-Warning $_.Exception.Message
        if(-not (Confirm-Choice 'Reintentar lectura de red con permisos de administrador, sin cambiar reglas?')){throw 'Investigacion cancelada o pendiente por permisos.'}
        $read=Invoke-ElevatedSecurity 'NetworkRead' @{}
        if($read.Status -ne 'Checked'){throw $read.Detail};$network=$read.Data
    }
    $network.Listeners|Format-Table Address,Port,ProcessId,Process,Scope,CanBlock -AutoSize|Out-Host
    $network.Routes|Format-Table|Out-Host
    Write-Host 'CanBlock permite proponer una regla reversible para ese programa y puerto. Puede afectar compartir archivos, juegos o servicios que uses.'
    $portText=Read-Host 'Puerto a bloquear (Enter solo investigar)';$port=0
    if(-not $portText){return $network}
    if(-not [int]::TryParse($portText,[ref]$port)){throw 'Puerto invalido.'}
    $matches=@($network.Listeners|Where-Object { $_.Port -eq $port -and $_.Scope -eq 'Network' -and $_.CanBlock })
    if($matches.Count -ne 1){throw 'Se requiere una escucha unica identificada; no se elige un proceso ambiguo.'}
    $entry=$matches[0];Write-Host "$($entry.Process) - $($entry.Executable) - TCP $port"
    if(Confirm-Choice 'Crear regla reversible de bloqueo entrante?'){
        $result=Invoke-ElevatedSecurity 'BlockListener' @{Port=$port;ProcessId=$entry.ProcessId;Program=$entry.Executable}
        $network|Add-Member -MemberType NoteProperty -Name ActionResult -Value $result
        $result|Format-List|Out-Host
    }
    return $network
}
function Add-DeepResult($Report,$Id,[scriptblock]$Read) {
    $result=Invoke-Check $Id $Read
    $Report.Checks=@($Report.Checks|Where-Object Id -ne $Id)+@($result)
    Add-ReportAnalysis $Report|Out-Null
    $result.Data|Format-List|Out-Host
    if($result.Error){Write-Warning $result.Error}
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
    $choice=Read-Host 'Comprobacion (Enter vuelve)'
    switch($choice){
        '1' {Add-DeepResult $Report 'NetworkInvestigation' {Show-NetworkInvestigation}}
        '2' {if(Confirm-Choice 'Consultar al router local sin modificar sus reglas?'){Add-DeepResult $Report 'Router' {Get-RouterMappings}}}
        '3' {if(Confirm-Choice 'Consultar Windows Update por red? No instala ni reinicia.'){Add-DeepResult $Report 'Updates' {Get-PendingUpdates}}}
        '4' {if(Confirm-Choice 'Consultar tabla oficial de soporte por Internet?'){Add-DeepResult $Report 'Support' {Get-SupportAssessment}}}
        '9' {if(Confirm-Choice 'Consultar CVRF Microsoft de los ultimos 3 meses?'){Add-DeepResult $Report 'CVE' {Get-CveCorrelation $Report}}}
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
    $exe=Get-KnownPython
    $scanner=Join-Path (Split-Path $PSScriptRoot -Parent) 'third_party\zero-breach\scanner.py'
    if((Get-FileHash -LiteralPath $scanner -Algorithm SHA256).Hash -ne 'BB0E6A7A36EE659C0494D02E9F7495D5FD4701F1AB7E57529E79925CB581AE15'){throw 'Motor IOC alterado; se rechaza su ejecucion.'}
    $folder=Get-StateFolder;$id=[guid]::NewGuid().ToString('N');$json=Join-Path $folder ('ioc-'+$id+'.json');$txt=Join-Path $folder ('ioc-'+$id+'.txt')
    $rule=$null
    try {
        $isolation=Invoke-ElevatedSecurity 'IsolatePython' @{}
        if($isolation.Status -ne 'Verified'){throw 'Aislamiento de red no verificado. No se ejecuta el analisis IOC.'}
        $rule=$isolation.Rule
        & $exe -I -X utf8 $scanner --no-menu --json $json --report $txt
        $code=$LASTEXITCODE
        if($code -notin @(0,2,3) -or -not (Test-Path -LiteralPath $json)){throw "Analisis incompleto/error de ejecucion ($code). Revisar archivos guardados en $folder"}
        $result=Read-IocReport $json
        if($result.ExitCode -ne $code){throw 'El exit code y el informe no concuerdan.'}
        return $result
    } finally {
        if($rule){Invoke-ElevatedSecurity 'UndoIsolation' @{Rule=$rule}|Out-Host}
    }
}
function Invoke-ElevatedSecurity([string]$Action,$Arguments) {
    if($Action -notin @('BlockListener','UndoBlock','IsolatePython','UndoIsolation','InstallSecurityUpdates','EnableRealtime','UpdateSignatures','QuickScan','NetworkRead')){throw 'Accion privilegiada no permitida.'}
    $id=[guid]::NewGuid().ToString('N')
    $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{Action=$Action;Arguments=$Arguments;Sid=(Get-Identity);Id=$id}|ConvertTo-Json -Compress)))
    $worker=Join-Path $PSScriptRoot 'SecurityWorker.ps1';$resultPath=Join-Path (Get-StateFolder) ('worker-'+$id+'.json')
    if(Test-IsAdmin){& $worker -Payload $payload}else{
        $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $child=Start-Process -FilePath $ps -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$worker+'"'),'-Payload',$payload) -PassThru -Wait
        if($child.ExitCode -ne 0){throw 'La operacion elevada fallo o fue cancelada.'}
    }
    if(-not (Test-Path -LiteralPath $resultPath)){throw 'Sin resultado verificable de la operacion elevada.'}
    Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
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
