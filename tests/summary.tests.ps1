param([string]$ResultPath)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Centinela.ps1') -LibraryOnly
$script:passed=0
function Assert($Value,$Name){if(-not $Value){throw "FAILED: $Name"};$script:passed++;Write-Output "PASS $Name"}
function New-Fixture {
    [pscustomobject]@{Version='test';Created=[datetime]::UtcNow.ToString('o');Gaps=@('coverage gap');Checks=@(
        [pscustomobject]@{Id='Defender';Status='Checked';Data=@([pscustomobject]@{AMRunningMode='Normal';AntivirusEnabled=$true;RealTimeProtectionEnabled=$true;IsTamperProtected=$true;AntivirusSignatureLastUpdated=[datetime]::Now;QuickScanEndTime=[datetime]::Now})}
        [pscustomobject]@{Id='Firewall';Status='Checked';Data=@([pscustomobject]@{Name='Public';Enabled=$true;DefaultInboundAction='Block'})}
        [pscustomobject]@{Id='ListeningTCP';Status='Checked';Data=@([pscustomobject]@{LocalAddress='127.0.0.1';LocalPort=80})}
    )}
}
$r=Add-ReportAnalysis (New-Fixture)
Assert ($r.Analysis.Alerts -eq 0 -and $r.Analysis.OK -eq 4) 'Healthy evidence produces favorable summary'
Assert ($r.Analysis.Review -eq 0) 'Loopback is not external exposure'
$r.Checks[0].Data[0].RealTimeProtectionEnabled=$false;$r=Add-ReportAnalysis $r
Assert (@($r.Analysis.Findings|Where-Object Action -eq EnableRealtime).Count -eq 1) 'Disabled protection proposes typed solution'
$r.Checks[0].Data[0].AMRunningMode='Passive';$r=Add-ReportAnalysis $r
Assert (@($r.Analysis.Findings|Where-Object Action -eq EnableRealtime).Count -eq 0) 'Passive Defender never forced active'
$r.Checks[0].Data[0].AntivirusSignatureLastUpdated=[datetime]::Now.AddDays(-10);$r=Add-ReportAnalysis $r
Assert (@($r.Analysis.Findings|Where-Object Action -eq UpdateSignatures).Count -eq 1) 'Old signatures propose update'
$r.Checks[0].Data[0].QuickScanEndTime=$null;$r=Add-ReportAnalysis $r
Assert (@($r.Analysis.Findings|Where-Object Action -eq QuickScan).Count -eq 1) 'Unknown recent scan proposes scan without infection claim'
$r.Checks[1].Data[0].Enabled=$false;$r=Add-ReportAnalysis $r
Assert (@($r.Analysis.Findings|Where-Object { $_.Level -eq 'Alert' -and $_.Title -like 'Firewall*' }).Count -eq 1) 'Disabled firewall creates alert'
$r.Checks[2].Data[0].LocalAddress='0.0.0.0';$r=Add-ReportAnalysis $r
Assert (@($r.Analysis.Findings|Where-Object Title -like 'Servicios escuchando*').Count -eq 1) 'Network listener produces contextual review'
$r.Checks[0].Status='Unavailable';$r.Checks[0]|Add-Member Error 'denied';$r=Add-ReportAnalysis $r
Assert ($r.Analysis.Unknown -eq 1) 'Unavailable check remains unknown'
$r|Add-Member ActionHistory @([pscustomobject]@{Action='QuickScan';Status='Requested';Detail='Pending completion'})
$text=Get-ReportText $r
Assert ($text.Contains('coverage gap') -and $text.Contains('denied') -and $text.Contains('Pending completion')) 'Summary includes gaps failures and action results'
$fixture=Join-Path $PSScriptRoot ('summary-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture|Out-Null
try {
    $script:desktopFixture=$fixture
    function Get-DesktopFolder {return $script:desktopFixture}
    $folder=Export-DesktopReport $r
    Assert (Test-Path -LiteralPath (Join-Path $folder 'Resumen.txt')) 'Desktop export includes readable text'
    $saved=Get-Content -LiteralPath (Join-Path $folder 'Diagnostico.json') -Raw|ConvertFrom-Json
    Assert ((Convert-ObservedDate $saved.Created) -eq (Convert-ObservedDate $r.Created) -and $saved.Analysis.Unknown -eq 1) 'Export uses cached analyzed snapshot'
    Assert ($saved.ActionHistory[0].Status -eq 'Requested') 'Export retains action verification status'
    $second=Export-DesktopReport $r
    Assert ($second -ne $folder) 'Exports never overwrite previous snapshot'
} finally {
    if(-not $fixture.StartsWith($PSScriptRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe test cleanup'}
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
$script:state=[pscustomobject]@{AMRunningMode='Normal';RealTimeProtectionEnabled=$false;AntivirusSignatureLastUpdated=[datetime]::Now.AddDays(-10);QuickScanEndTime=[datetime]::Now.AddDays(-10)}
function Get-MpComputerStatus {param($ErrorAction) return $script:state}
function Test-IsAdmin {return $false}
$script:writes=0
function Set-MpPreference {param($DisableRealtimeMonitoring,$ErrorAction) $script:writes++}
$result=Invoke-SecuritySolution 'EnableRealtime'
Assert ($result.Status -eq 'NeedsAdmin' -and $script:writes -eq 0) 'No implicit elevation or write without admin'
function Test-IsAdmin {return $true}
$result=Invoke-SecuritySolution 'EnableRealtime'
Assert ($result.Status -eq 'Failed') 'Ignored preference change never verified'
function Set-MpPreference {param($DisableRealtimeMonitoring,$ErrorAction) $script:state.RealTimeProtectionEnabled=$true}
$result=Invoke-SecuritySolution 'EnableRealtime'
Assert ($result.Status -eq 'Verified') 'Realtime activation verified by requery'
function Update-MpSignature {param($ErrorAction) throw 'fixture denied'}
$result=Invoke-SecuritySolution 'UpdateSignatures'
Assert ($result.Status -eq 'Failed') 'Update failure reported'
function Update-MpSignature {param($ErrorAction) }
$result=Invoke-SecuritySolution 'UpdateSignatures'
Assert ($result.Status -eq 'Failed') 'Stale post-update date never verified'
function Update-MpSignature {param($ErrorAction) $script:state.AntivirusSignatureLastUpdated=[datetime]::Now}
$result=Invoke-SecuritySolution 'UpdateSignatures'
Assert ($result.Status -eq 'Verified') 'Recent definitions verified'
function Start-MpScan {param($ScanType,$ErrorAction) }
$result=Invoke-SecuritySolution 'QuickScan'
Assert ($result.Status -eq 'Requested') 'Scan request never claimed complete without evidence'
$script:state.AMRunningMode='Passive';$script:writes=0
$result=Invoke-SecuritySolution 'EnableRealtime'
Assert ($result.Status -eq 'Failed' -and $script:writes -eq 0) 'Passive mode rechecked at apply time'
$denied=$false;try{Invoke-SecuritySolution 'arbitrary-command'}catch{$denied=$true}
Assert $denied 'Arbitrary action rejected'
$future=New-Fixture;$future.Checks[0].Data[0].AntivirusSignatureLastUpdated=[datetime]::Now.AddDays(20);$future=Add-ReportAnalysis $future
Assert (@($future.Analysis.Findings|Where-Object { $_.Title -eq 'Fecha de firmas' -and $_.Level -eq 'Unknown' }).Count -eq 1) 'Future dates never claim recent signatures'
$script:called=0
function Invoke-SecuritySolution {param($Action) $script:called++}
function Read-Host {param($Prompt) return '1'}
function Confirm-Choice {param($Question) return $false}
$cancel=New-Fixture;$cancel.Checks[0].Data[0].RealTimeProtectionEnabled=$false;$cancel=Add-ReportAnalysis $cancel
Show-Solutions $cancel
Assert ($script:called -eq 0) 'Cancelled proposal performs no action'
$summary=[pscustomobject]@{Engine=$PSVersionTable.PSVersion.ToString();Passed=$script:passed;Boundary='Synthetic reports and mocked Defender commands; isolated desktop export fixture. No real security changes.'}
if($ResultPath){$summary|ConvertTo-Json|Set-Content -LiteralPath $ResultPath -Encoding UTF8}
$summary|Format-List
