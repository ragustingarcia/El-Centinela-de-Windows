# Pruebas de la auditoria 0.3.1: reproducen los 8 fallos de la primera corrida real (Windows 11 build 26300)
# con cmdlets de Windows simulados. Corre en Windows PowerShell 5.1 y en PowerShell 7 (tambien Linux).
param([string]$ResultPath,[switch]$ShowOutput)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Centinela.ps1') -LibraryOnly
$script:passed=0
function Assert($ok,$name){if(-not $ok){throw "FAILED: $name"};$script:passed++;Write-Output "PASS $name"}
function Capture([scriptblock]$Run){ (& $Run *>&1 | Out-String -Width 220) }

# ---------- Simulacion de la PC del usuario ----------
if(-not $env:SystemRoot){$env:SystemRoot='C:\WINDOWS'}
$script:state=Join-Path ([IO.Path]::GetTempPath()) ('centinela-audit-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:state|Out-Null
function Get-StateFolder {return $script:state}
function Get-Identity {return 'S-1-5-21-0-0-0-1001'}
$script:admin=$false
function Test-IsAdmin {return $script:admin}
$script:uac=[pscustomobject]@{EnableLUA=1;ConsentPromptBehaviorAdmin=5;PromptOnSecureDesktop=1;ProcessElevated=$false}
function Get-UacStatus {return $script:uac}
function Get-MpComputerStatus {param($ErrorAction) [pscustomobject]@{AntivirusEnabled=$true;RealTimeProtectionEnabled=$true;AMRunningMode='Normal';IsTamperProtected=$true;AntivirusSignatureLastUpdated=[datetime]::Now.AddHours(-12);QuickScanEndTime=[datetime]::Now.AddDays(-1)}}
function Get-AntivirusHealth {[pscustomobject]@{Code=0;Health='Good';Source='mock';Scope='mock'}}
function Get-NetFirewallProfile {param($PolicyStore,$ErrorAction) foreach($n in 'Domain','Private','Public'){[pscustomobject]@{Name=$n;Enabled='True';DefaultInboundAction='NotConfigured';DefaultOutboundAction='NotConfigured'}}}
$script:procs=@(
 [pscustomobject]@{ProcessId=4;Name='System';ExecutablePath=$null}
 [pscustomobject]@{ProcessId=1100;Name='svchost.exe';ExecutablePath='C:\WINDOWS\system32\svchost.exe'}
 [pscustomobject]@{ProcessId=13624;Name='OneDrive.Sync.Service.exe';ExecutablePath='C:\Program Files\Microsoft OneDrive\OneDrive.Sync.Service.exe'}
 [pscustomobject]@{ProcessId=37548;Name='codex.exe';ExecutablePath='C:\Users\ga_tu\AppData\Local\OpenAI\Codex\bin\x\codex.exe'}
 [pscustomobject]@{ProcessId=6908;Name='postgres.exe';ExecutablePath='C:\Program Files\PostgreSQL\17\bin\postgres.exe'}
 [pscustomobject]@{ProcessId=33260;Name='steamwebhelper.exe';ExecutablePath='C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe'}
)
function Get-CimInstance {param($ClassName,$Namespace,$Filter,$OperationTimeoutSec)
  switch($ClassName){
   'Win32_OperatingSystem' {[pscustomobject]@{Caption='Microsoft Windows 11 Home Single Language';Version='10.0.26300';BuildNumber='26300';LastBootUpTime=[datetime]::Now}}
   'Win32_Process' {if($Filter -match 'ProcessId=(\d+)'){$script:procs|Where-Object ProcessId -eq ([int]$Matches[1])}else{$script:procs}}
   'Win32_Service' {[pscustomobject]@{Name='x';State='Running';PathName='C:\x.exe --token=SECRETO123';StartMode='Auto'}}
   default {}
  }}
function C($la,$lp,$pid_,$ra='0.0.0.0',$rp=0){[pscustomobject]@{LocalAddress=$la;LocalPort=$lp;OwningProcess=$pid_;RemoteAddress=$ra;RemotePort=$rp}}
# Lo que devolvio "Get-NetTCPConnection -State Listen" en la PC real: mezcla PID 0 (no son escuchas) y escuchas reales.
$script:tcp=@(
 (C '::1' 42050 13624 '::'),(C '192.168.1.234' 55829 0 '20.1.1.1' 443),(C '192.168.1.234' 55801 0),(C '192.168.1.234' 50686 37548),
 (C '0.0.0.0' 5432 6908),(C '::' 5432 6908 '::'),(C '192.168.1.234' 139 4),(C '0.0.0.0' 135 1100),(C '0.0.0.0' 445 4)
)
function Get-NetTCPConnection {param($State,$LocalPort,$ErrorAction) if($LocalPort){$script:tcp|Where-Object LocalPort -eq $LocalPort}else{$script:tcp}}
# Fuente .NET independiente: las filas PID 0 no figuran como LISTEN.
function Get-DotNetTcpListeners {'::1|42050','192.168.1.234|50686','0.0.0.0|5432','::|5432','192.168.1.234|139','0.0.0.0|135','0.0.0.0|445'}
function Get-ScheduledTask {[pscustomobject]@{TaskPath='\';TaskName='t';State='Ready';Actions=@([pscustomobject]@{Execute='x.exe';Arguments='--password=hunter2'})}}
function Get-AppxPackage {}
function Get-Process {param($Id,$ErrorAction) foreach($p in $script:procs){[pscustomobject]@{Id=$p.ProcessId;ProcessName=([string]$p.Name -replace '\.exe$','')}}}
function Read-PrivacyValue($Name){return 1}
function Get-NetFirewallRule {param($Name,$PolicyStore,$Direction,$Enabled,$ErrorAction) if($Name){[pscustomobject]@{Enabled='True';Action='Block'}}else{[pscustomobject]@{Name='r1';DisplayName='Regla';Action='Allow';Profile='Any';PolicyStoreSourceType='Local';EnforcementStatus='OK'}}}
function Get-NetFirewallPortFilter {process{[pscustomobject]@{Protocol='TCP';LocalPort='Any'}}}
function Get-NetFirewallApplicationFilter {process{[pscustomobject]@{Program='Any'}}}
function Get-NetFirewallAddressFilter {process{[pscustomobject]@{LocalAddress='Any';RemoteAddress='Any'}}}
function Get-NetRoute {param($ErrorAction) [pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceAlias='Wi-Fi';NextHop='192.168.1.1';RouteMetric=0}}
function Get-NetAdapter {param([switch]$IncludeHidden,$ErrorAction) [pscustomobject]@{Name='Wi-Fi';InterfaceDescription='Intel Wi-Fi 6 AX201';Status='Up'}}
function Get-VpnConnection {param([switch]$AllUserConnection,$ErrorAction)}
$script:elevated=@()
function Invoke-ElevatedSecurity {param($Action,$Arguments) $script:elevated+=,@($Action,$Arguments);[pscustomobject]@{Action=$Action;Status='RuleVerified';Detail='mock'}}
$script:answers=New-Object 'Collections.Generic.Queue[string]'
function Read-Host {param($Prompt) if($ShowOutput){Write-Host "$Prompt`: " -NoNewline};$a=if($script:answers.Count){$script:answers.Dequeue()}else{''};if($ShowOutput){Write-Host $a};return $a}
function Feed([string[]]$a){$script:answers.Clear();foreach($x in $a){$script:answers.Enqueue($x)}}

try {
# ---------- Bug 4: escuchas falsas (PID 0) y efimeras ----------
$sockets=@(Get-ListeningSockets)
Assert (@($sockets|Where-Object OwningProcess -eq 0).Count -eq 0) 'Bug4: PID 0 (System Idle Process) nunca se informa como escucha'
Assert ($sockets.Count -eq 7) 'Bug4: solo quedan las 7 escuchas confirmadas por la fuente .NET'
$net=Get-NetworkInvestigation
Assert (@($net.Listeners|Where-Object {$_.Port -eq 5432}).Count -eq 1) 'Bug4: IPv4+IPv6 del mismo programa/puerto se agrupan'
Assert (@($net.Listeners|Where-Object {$_.Process -eq 'System Idle Process'}).Count -eq 0) 'Bug4: tabla sin System Idle Process'

# ---------- Diagnostico completo (opcion 1) ----------
$report=Get-SecurityReport
$pg=@($report.Analysis.Findings|Where-Object Title -like '*PostgreSQL*')
Assert ($pg.Count -eq 1 -and $pg[0].Level -eq 'Review' -and $pg[0].Detail -match 'localhost') 'Bug7: postgres en 0.0.0.0:5432 se marca y se explica'
Assert ($report.Analysis.State -eq 'REVISAR') 'Bug8: veredicto claro REVISAR'
Assert (@($report.Analysis.Findings|Where-Object Level -eq Pending).Count -eq 1 -and $report.Analysis.Unknown -eq 0) 'Bug8: 7 pendientes agrupados en una linea, no 7 "Sin comprobar"'
$text=Get-ReportText $report
Assert ($text -match 'VEREDICTO: REVISAR' -and ($text -split "`n").Count -lt 30) 'Bug8: resumen corto con veredicto'
if($ShowOutput){Write-Host $text}
Assert (-not ($text -match 'System Idle')) 'Bug4: resumen sin escuchas falsas'

# ---------- Bug 5 + 6: flujo 8 > 1 con "6" escrito ----------
Feed @('6')
$out=Capture {Add-DeepResult $report 'NetworkInvestigation' {Show-NetworkInvestigation}}
if($ShowOutput){Write-Host $out}
Assert (($report.Checks|Where-Object Id -eq NetworkInvestigation).Status -eq 'Checked') 'Bug5: una entrada invalida ya no borra la investigacion'
Assert ($out -match 'numero de la columna N') 'Bug5: el mensaje explica que se pide el numero de fila'
Assert (-not ($out -match 'Listeners\s+:|@\{Address=')) 'Bug6: sin volcado crudo de objetos PowerShell'
Assert ($out -match 'postgres' -and $out -match 'todas las redes') 'Bug6: tabla legible con programa y alcance'
Feed @('1','s')
$script:elevated=@();$o2=Capture {Add-DeepResult $report 'NetworkInvestigation' {Show-NetworkInvestigation}};if($ShowOutput){Write-Host $o2}
$first=@($net.Listeners|Where-Object {$_.Scope -ne 'Loopback' -and -not $_.IsWindows})[0]
Assert ($script:elevated.Count -eq 1 -and $script:elevated[0][1].Port -eq $first.Port) 'Bug5: el numero de fila elige la fila correcta para bloquear'
Feed @('5432','s')
$script:elevated=@();$o2=Capture {Add-DeepResult $report 'NetworkInvestigation' {Show-NetworkInvestigation}};if($ShowOutput){Write-Host $o2}
Assert ($script:elevated.Count -eq 1 -and $script:elevated[0][1].Port -eq 5432) 'Bug5: tambien acepta un puerto que figure en la tabla'

# ---------- Bug 3: titulo en espanol ----------
$report.Checks=@($report.Checks|Where-Object Id -ne 'NetworkInvestigation')+@([pscustomobject]@{Id='NetworkInvestigation';Status='Unavailable';CheckedAt='x';Data=@();Error='Acceso denegado'})
Add-ReportAnalysis $report|Out-Null
Assert (@($report.Analysis.Findings|Where-Object Title -eq 'NetworkInvestigation').Count -eq 0 -and @($report.Analysis.Findings|Where-Object Title -eq 'Red, procesos y puertos').Count -eq 1) 'Bug3: nunca se muestra el id interno'

# ---------- Bug 2: UPnP ----------
$msg=$null;try{Invoke-BoundedRead {throw 'El router no expone mapeos UPnP'} 20}catch{$msg=$_.Exception.Message}
Assert ($msg -match 'no se completo: El router no expone mapeos UPnP') 'Bug2: el motivo real del fallo del job se informa (Start-Job real)'
Assert ((Get-FailureAdvice 'Router' $msg) -notmatch 'permisos') 'Bug2: no se sugiere "revisar permisos" para un router sin UPnP'
$report.Checks=@($report.Checks|Where-Object Id -ne 'Router')+@([pscustomobject]@{Id='Router';Status='Checked';CheckedAt='x';Data=@([pscustomobject]@{UPnPAvailable=$false;Mappings=@();Scope='s'})})
Add-ReportAnalysis $report|Out-Null
Assert (@($report.Analysis.Findings|Where-Object {$_.Title -eq 'Router (UPnP)' -and $_.Level -eq 'OK'}).Count -eq 1) 'Bug2: router sin UPnP es un dato favorable, no un error'

# ---------- Bug 1: IOC con menu elevado ----------
$script:admin=$true;$script:uac.EnableLUA=0
$msg=$null;try{Invoke-IocScan}catch{$msg=$_.Exception.Message}
Assert ($msg -match 'UAC' -and $msg -match 'desactivado') 'Bug1: explica que UAC desactivado eleva todo el menu'
$script:uac.EnableLUA=1
$msg=$null;try{Invoke-IocScan}catch{$msg=$_.Exception.Message}
Assert ($msg -match 'Ejecutar como administrador') 'Bug1: explica consola abierta como administrador'
$script:uac.EnableLUA=0;$r2=Get-SecurityReport
Assert ($r2.Analysis.State -eq 'EN RIESGO' -and @($r2.Analysis.Findings|Where-Object Title -like '*UAC*desactivado*').Count -eq 1) 'Nuevo: UAC desactivado es alerta EN RIESGO'
$script:admin=$false;$script:uac.EnableLUA=1

# ---------- Soporte Insider build 26300 ----------
function Get-OSLicensing {[pscustomobject]@{Caption='Windows 11 Home';Edition='Core';DisplayVersion='25H2';Build='26300'}}
function Get-InsiderInfo {[pscustomobject]@{IsInsider=$true;Channel='Dev'}}
$s=Get-SupportAssessment
Assert ($s.Status -eq 'Insider' -and $s.Detail -match 'Insider') 'Build Insider 26300 se identifica sin consultar Internet'

# ---------- CVE: boletin del mes no publicado ----------
$script:calls=0
function Invoke-WebRequest {param($Uri,$Headers,[switch]$UseBasicParsing,$TimeoutSec,$ErrorAction) $script:calls++;if($script:calls -eq 1){throw '(404) Not Found'};[pscustomobject]@{RawContentLength=10;Content='{"Vulnerability":[{"CVE":"CVE-2026-1","Title":{"Value":"t"},"Remediations":[{"Description":{"Value":"5070000"}}]}]}'}}
$cr=[pscustomobject]@{Checks=@([pscustomobject]@{Id='Updates';Status='Checked';Data=@([pscustomobject]@{Updates=@([pscustomobject]@{KB=@('5070000')})})})}
$cve=Get-CveCorrelation $cr
Assert (@($cve.Gaps).Count -eq 0 -and @($cve.Matches).Count -eq 1) 'CVE: mes en curso sin publicar no es falta de cobertura'

# ---------- Exportacion sin secretos ----------
$red=Protect-ExportText '{"Arguments":"--password=hunter2","PathName":"C:\\x.exe --token=SECRETO123","ok":"api_key: abc"}'
Assert (-not ($red -match 'hunter2|SECRETO123|abc"')) 'Exportacion oculta password/token/api_key'

# ---------- Menu completo simulado (opcion 1 > S, 8 > 2, 7, 8 > 6, 0) ----------
function New-Object {param($TypeName,$ArgumentList,$ComObject) if($ComObject){throw 'COM no disponible en la prueba'};if($null -eq $ArgumentList){Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName}else{Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList}}
Feed @('1','s','','7','','8','6','s','0')
$out=Capture {Start-CentinelaMenu}
if($ShowOutput){Write-Host $out}
Assert ($out -match 'VEREDICTO' -and $out -match 'Comprobaciones avanzadas sin hacer' -and $out -notmatch 'NetworkInvestigation\s*$') 'Menu: flujo completo sin ids internos'
Assert ($out -match 'Python no detectado|IOC') 'Menu: 8 > 6 sin admin llega al motor IOC (no se bloquea por falso administrador)'
} finally {
  if($script:state.StartsWith([IO.Path]::GetTempPath())){Remove-Item -LiteralPath $script:state -Recurse -Force -ErrorAction SilentlyContinue}
}
$summary=[pscustomobject]@{Engine=$PSVersionTable.PSVersion.ToString();Passed=$script:passed;Boundary='Cmdlets de Windows simulados con los datos de la primera corrida real; Start-Job real. Sin cambios reales.'}
if($ResultPath){$summary|ConvertTo-Json|Set-Content -LiteralPath $ResultPath -Encoding UTF8}
$summary|Format-List
