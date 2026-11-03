param([string]$ResultPath)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Centinela.ps1') -LibraryOnly
$script:passed=0
function Assert($ok,$name){if(-not $ok){throw "FAILED $name"};$script:passed++;Write-Output "PASS $name"}
function Reject([scriptblock]$Run,$name){$blocked=$false;try{& $Run|Out-Null}catch{$blocked=$true};Assert $blocked $name}
foreach($path in Get-ChildItem -LiteralPath (Split-Path $PSScriptRoot -Parent) -Filter '*.ps1' -Recurse){
    $errors=$null;$tokens=$null;[Management.Automation.Language.Parser]::ParseFile($path.FullName,[ref]$tokens,[ref]$errors)|Out-Null
    Assert ($errors.Count -eq 0) ('Parse '+$path.Name)
}
function Get-OSLicensing {[pscustomobject]@{Caption='Windows 11';Edition='Core';DisplayVersion='26H2';Build='26300'}}
function Invoke-WebRequest {param($Uri,$Headers,[switch]$UseBasicParsing,$TimeoutSec,$ErrorAction) [pscustomobject]@{Content='<tr><td>Version 26H2</td><td>Sep 29, 2026</td><td>Oct 10, 2028</td></tr>'}}
$support=Get-SupportAssessment
Assert ($support.EndDate.Year -eq 2028 -and $support.Status -eq 'InSupportUntil') 'Support parsed by version from source table'
function Invoke-WebRequest {param($Uri,$Headers,[switch]$UseBasicParsing,$TimeoutSec,$ErrorAction) [pscustomobject]@{Content='<tr><td>Version 26H2</td><td><local-time datetime="9/29/2026 8:00:00 AM">9/29/2026</local-time></td><td><local-time datetime="10/10/2028 6:59:59 AM">10/10/2028</local-time></td></tr>'}}
Assert ((Get-SupportAssessment).EndDate.Year -eq 2028) 'Real Microsoft numeric datetime layout parsed'
function Invoke-WebRequest {param($Uri,$Headers,[switch]$UseBasicParsing,$TimeoutSec,$ErrorAction) [pscustomobject]@{Content='unrecognized layout'}}
Assert ((Get-SupportAssessment).Status -eq 'Unknown') 'Unrecognized support page is unknown'
$script:rules=0;$script:journal=0
function Test-IsAdmin {return $false}
Reject {Block-VerifiedListener 5000 100 'C:\App\app.exe'} 'Block requires elevation'
function Test-IsAdmin {return $true}
function New-NetFirewallRule {param($Name,$DisplayName,$Direction,$Action,$Protocol,$LocalPort,$Program,$Profile,$ErrorAction) if(-not $script:journal){throw 'Backup missing'};$script:rules++}
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec) [pscustomobject]@{ProcessId=100;Name='app.exe';ExecutablePath='C:\App\app.exe'}}
function Get-NetTCPConnection {param($State,$LocalPort,$ErrorAction) [pscustomobject]@{OwningProcess=100;LocalPort=5000}}
function Get-StateFolder {return $PSScriptRoot}
function Save-Journal {param($Journal,$Path) $script:journal++}
function Get-NetFirewallRule {param($Name,$PolicyStore,$ErrorAction) [pscustomobject]@{Enabled='True';Action='Block'}}
Reject {Block-VerifiedListener 3389 100 'C:\App\app.exe'} 'Remote administration port protected'
Reject {Block-VerifiedListener 5000 4 'C:\App\app.exe'} 'System process protected'
Reject {Block-VerifiedListener 5000 100 'C:\Changed.exe'} 'Changed program rejected'
Assert ($script:rules -eq 0) 'No writes for rejected selection'
$result=Block-VerifiedListener 5000 100 'C:\App\app.exe'
Assert ($result.Status -eq 'RuleVerified' -and $script:rules -eq 1 -and $script:journal -eq 2) 'Rule preceded by journal and verified after creation'
Reject {Undo-ListenerBlock 'WindowsDefenderRule'} 'Undo cannot target arbitrary firewall rule'
Reject {Install-SelectedSecurityUpdates @('invalid')} 'Malformed update ID refused before WUA'
Reject {Invoke-ElevatedSecurity 'arbitrary-command' @{}} 'Unknown privileged operation rejected'
$script:reboot=$false;$script:searchStatus=2;$script:downloadStatus=2;$script:installs=0
$id='abcdef00-0000-0000-0000-000000000001'
$script:wuaUpdates=@([pscustomobject]@{Identity=[pscustomobject]@{UpdateID=$id};EulaAccepted=$true;Categories=@([pscustomobject]@{CategoryID='0FA1201D-4330-4FA8-8AE9-B877473B6441'})})
$script:searcher=[pscustomobject]@{};$script:searcher|Add-Member ScriptMethod Search {param($query) [pscustomobject]@{ResultCode=$script:searchStatus;Updates=$script:wuaUpdates}}
$script:downloader=[pscustomobject]@{Updates=$null};$script:downloader|Add-Member ScriptMethod Download {[pscustomobject]@{ResultCode=$script:downloadStatus}}
$script:installer=[pscustomobject]@{Updates=$null};$script:installer|Add-Member ScriptMethod Install {$script:installs++;[pscustomobject]@{ResultCode=2;RebootRequired=$true}}
$script:session=[pscustomobject]@{}
$script:session|Add-Member ScriptMethod CreateUpdateSearcher {return $script:searcher}
$script:session|Add-Member ScriptMethod CreateUpdateDownloader {return $script:downloader}
$script:session|Add-Member ScriptMethod CreateUpdateInstaller {return $script:installer}
function New-Object {param($TypeName,$ArgumentList,$ComObject)
    switch($ComObject){
        'Microsoft.Update.SystemInfo' {return [pscustomobject]@{RebootRequired=$script:reboot}}
        'Microsoft.Update.Session' {return $script:session}
        'Microsoft.Update.UpdateColl' {$c=[pscustomobject]@{Count=0};$c|Add-Member ScriptMethod Add {param($u) $this.Count++};return $c}
        default {if($null -eq $ArgumentList){Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName}else{Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList}}
    }
}
$install=Install-SelectedSecurityUpdates @($id)
Assert ($script:installs -eq 1 -and $install.RebootRequired -and $install.Status -eq 'InstalledPendingVerification') 'Approved security update installation preserves pending reboot status'
$script:reboot=$true
Reject {Install-SelectedSecurityUpdates @($id)} 'Existing reboot pending prevents new installation'
$script:reboot=$false;$script:searchStatus=3
Reject {Install-SelectedSecurityUpdates @($id)} 'Partial WUA search prevents installation'
$script:searchStatus=2;$script:downloadStatus=3
Reject {Install-SelectedSecurityUpdates @($id)} 'Partial download prevents installation'
$script:downloadStatus=2
Reject {Install-SelectedSecurityUpdates @('abcdef00-0000-0000-0000-000000000002')} 'Changed approved update list prevents installation'
Assert ($script:installs -eq 1) 'Rejected WUA cases never call installer'
$fixture=Join-Path $PSScriptRoot ('deep-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $fixture|Out-Null
try{
    $external=Join-Path $fixture 'external.json'
    @{Schema='Centinela.ExternalProbe.1';Target='203.0.113.1';At=[datetime]::UtcNow.ToString('o');ConfirmedExternal=$true;Results=@(@{Port=5000;Status='Reachable'})}|ConvertTo-Json -Depth 5|Set-Content $external
    $import=Import-ExternalProbe $external
    Assert ($import.Results[0].Status -eq 'Reachable' -and $import.Provenance -like 'Importado*') 'External evidence keeps provenance and reachability'
    @{Schema='bad';Target='x';ConfirmedExternal=$false}|ConvertTo-Json|Set-Content $external
    Reject {Import-ExternalProbe $external} 'Unconfirmed external evidence rejected'
    $ioc=Join-Path $fixture 'ioc.json'
    @{schema_version='1.6';exit_code=3;verdict=@{status='NO_KNOWN_INDICATORS_WITH_GAPS'};coverage=@{not_checked=@('denied')};must_relay=@('scope limited')}|ConvertTo-Json -Depth 5|Set-Content $ioc
    $import=Read-IocReport $ioc
    Assert ($import.ExitCode -eq 3 -and $import.Coverage.not_checked[0] -eq 'denied') 'IOC gaps preserved'
    @{schema_version='unknown';exit_code=0}|ConvertTo-Json|Set-Content $ioc
    Reject {Read-IocReport $ioc} 'Unknown IOC contract never accepted as clean'
}finally{
    if(-not $fixture.StartsWith($PSScriptRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe cleanup'}
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
$scanner=Join-Path (Split-Path $PSScriptRoot -Parent) 'third_party/zero-breach/scanner.py'
Assert ((Get-FileHash -LiteralPath $scanner -Algorithm SHA256).Hash -eq 'BB0E6A7A36EE659C0494D02E9F7495D5FD4701F1AB7E57529E79925CB581AE15') 'Bundled IOC engine matches reviewed hash'
$contract=(& python -I -X utf8 $scanner --describe)|ConvertFrom-Json
Assert ($LASTEXITCODE -eq 0 -and $contract.schema_version -eq '1.6') 'Bundled IOC describe contract compatible without running scan'
$summary=[pscustomobject]@{Engine=$PSVersionTable.PSVersion.ToString();Passed=$script:passed;Boundary='Mocked networking, support responses, firewall and update commands; synthetic IOC/external reports. No real network changes or updates installed.'}
if($ResultPath){$summary|ConvertTo-Json|Set-Content -LiteralPath $ResultPath -Encoding UTF8}
$summary|Format-List
