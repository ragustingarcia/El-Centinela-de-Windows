param([string]$ResultPath)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Centinela.ps1') -LibraryOnly
$script:passed=0
function Assert($ok,$name){if(-not $ok){throw "FAILED: $name"};$script:passed++;Write-Output "PASS $name"}
function Reject([scriptblock]$Run,$name){$failed=$false;try{& $Run|Out-Null}catch{$failed=$true};Assert $failed $name}
function Read-Host {param($Prompt) return $script:answer}
foreach($script:answer in @('salir','stop','s ahora','yes','no','')){Assert (-not (Confirm-Choice 'fixture')) "Reject [$script:answer]"}
foreach($script:answer in @('s','SI',' sí ')){Assert (Confirm-Choice 'fixture') "Accept [$script:answer]"}
$fixture=Join-Path $PSScriptRoot ('fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture|Out-Null
try {
 Assert ((Test-LocalPath $fixture) -eq $fixture) 'Local fixture accepted'
 Reject {Test-LocalPath '\\server\share\file'} 'UNC refused'
 Reject {Test-LocalPath 'relative\file'} 'Relative path refused'
 Reject {Test-LocalPath ($fixture+'\..\outside')} 'Noncanonical path refused'
 Protect-StateFolder $fixture
 Assert ((Get-Acl -LiteralPath $fixture).AreAccessRulesProtected) 'Journal ACL inheritance disabled'
 $script:values=@{};$script:failWrite=$false
 function Read-PrivacyValue($Name){return $script:values[$Name]}
 function Write-PrivacyValue($Name,$Value){if($script:failWrite){throw 'fixture rejected'};if($null -eq $Value){$script:values.Remove($Name)}else{$script:values[$Name]=$Value}}
 $name=$script:PrivacyNames[0];$script:values[$name]=[int]1
 $plan=@(New-PrivacyPlan);Assert ($plan.Count -eq $script:PrivacyNames.Count) 'Plan captures absent values'
 $journal=Join-Path $fixture 'journal.json';$result=Invoke-PrivacyPlan $plan $journal
 Assert (@($result.Entries|Where-Object Status -ne Verified).Count -eq 0) 'Applied values verified'
 Assert (@(New-PrivacyPlan).Count -eq 0) 'Second run idempotent'
 $script:values[$name]=[int]2;$result=Undo-Privacy $journal
 Assert ($script:values[$name] -eq 2) 'Undo preserves later changes'
 Assert (-not $script:values.ContainsKey($script:PrivacyNames[1])) 'Undo restores original absence'
 $script:values[$name]=[int]0;$result=Undo-Privacy $journal
 Assert ($script:values[$name] -eq 1) 'Undo restores original DWORD'
 $script:failWrite=$true;$result=Invoke-PrivacyPlan @(New-PrivacyPlan) (Join-Path $fixture 'failed.json')
 Assert (@($result.Entries|Where-Object Status -eq Verified).Count -eq 0) 'Failed writes never reported verified'
 $script:failWrite=$false
 $plan=@(New-PrivacyPlan);$script:values[$name]=[int]3;$result=Invoke-PrivacyPlan $plan (Join-Path $fixture 'changed.json')
 Assert ($script:values[$name] -eq 3) 'Stale plan preserves current state'
 Reject {Invoke-PrivacyPlan @([pscustomobject]@{Name='arbitrary';After=0}) $journal} 'Arbitrary target refused'
 Reject {Invoke-PrivacyPlan @(New-PrivacyPlan) (Join-Path $fixture 'missing\journal.json')} 'Backup failure prevents changes'
 $bad=Get-Content -LiteralPath $journal -Raw|ConvertFrom-Json;$bad.Sid='other';Save-Journal $bad (Join-Path $fixture 'bad.json')
 Reject {Undo-Privacy (Join-Path $fixture 'bad.json')} 'Wrong identity refused'
 $script:tempRoot=Join-Path $fixture 'Temp';New-Item -ItemType Directory -Path $script:tempRoot|Out-Null
 function Get-TempRoot {return $script:tempRoot}
 $old=Join-Path $script:tempRoot 'old.tmp';$recent=Join-Path $script:tempRoot 'recent.tmp'
 [IO.File]::WriteAllText($old,'old');[IO.File]::WriteAllText($recent,'recent')
 [IO.File]::SetCreationTimeUtc($old,[DateTime]::UtcNow.AddDays(-30));[IO.File]::SetLastWriteTimeUtc($old,[DateTime]::UtcNow.AddDays(-30))
 $plan=@(Get-TempPlan);Assert ($plan.Count -eq 1 -and $plan[0].Path -eq $old) 'Only old files selected'
 Reject {Get-TempPlan -Days 1} 'Unsafe age refused'
 [IO.File]::WriteAllText($old,'changed');$result=Invoke-TempPlan $plan
 Assert ($result.Deleted -eq 0 -and $result.Skipped -eq 1) 'Changed file preserved'
 [IO.File]::SetCreationTimeUtc($old,[DateTime]::UtcNow.AddDays(-30));[IO.File]::SetLastWriteTimeUtc($old,[DateTime]::UtcNow.AddDays(-30))
 $result=Invoke-TempPlan @(Get-TempPlan)
 Assert ($result.Deleted -eq 1 -and $result.Bytes -eq 7) 'Real fixture deletion and bytes verified'
 Assert (Test-Path -LiteralPath $recent) 'Recent file preserved'
 $outside=Join-Path $fixture 'outside.txt';[IO.File]::WriteAllText($outside,'keep');$item=Get-Item -LiteralPath $outside
 $result=Invoke-TempPlan @([pscustomobject]@{Path=$outside;Length=$item.Length;Modified=$item.LastWriteTimeUtc.Ticks;Created=$item.CreationTimeUtc.Ticks})
 Assert ($result.Deleted -eq 0 -and (Test-Path -LiteralPath $outside)) 'Outside deletion refused'
 $link=Join-Path $script:tempRoot 'redirect';New-Item -ItemType Junction -Path $link -Target $fixture|Out-Null
 Reject {Test-LocalPath (Join-Path $link 'outside.txt')} 'Junction ancestor refused'
 Assert (@(Get-TempPlan).Count -eq 0) 'Walker skips redirected subtree'
 [IO.Directory]::Delete($link)
 $result=Invoke-Check 'failure' {throw 'fixture unavailable'};Assert ($result.Status -eq 'Unavailable') 'Read failure is unavailable'
 $result=Invoke-Check 'empty' {return @()};Assert ($result.Status -eq 'Checked') 'Empty differs from failure'
 $export=Join-Path $fixture 'report.json';Export-Report ([pscustomobject]@{Status='Partial';Value='fixture'}) $export
 Assert ((Get-Content -LiteralPath $export -Raw|ConvertFrom-Json).Status -eq 'Partial') 'Report JSON preserves result'
 Reject {Export-Report ([pscustomobject]@{Value='overwrite'}) $export} 'Report refuses overwrite'
 foreach($command in @('Get-CimInstance','Get-MpComputerStatus','Get-NetFirewallProfile','Get-NetTCPConnection','Get-ScheduledTask','Get-AppxPackage')) {
  Set-Item ('Function:\'+$command) { [pscustomobject]@{Name='fixture';StartMode='Auto';Actions=@()} }
 }
 # The registry reader is mocked; the optional Run key is queried read-only.
 $report=Get-SecurityReport
 Assert ($report.Checks.Count -eq 10 -and $report.Gaps.Count -gt 0) 'Report carries catalogue and coverage limits'
 function Get-MpComputerStatus {throw 'fixture denied'}
 $report=Get-SecurityReport
 Assert (@($report.Checks|Where-Object { $_.Id -eq 'Defender' -and $_.Status -eq 'Unavailable' }).Count -eq 1) 'Report propagates failed security check'
} finally {
 if(Test-Path -LiteralPath $fixture){
  if(-not $fixture.StartsWith($PSScriptRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe cleanup'}
  $link=Join-Path $fixture 'Temp\redirect';if(Test-Path -LiteralPath $link){[IO.Directory]::Delete($link)}
  Remove-Item -LiteralPath $fixture -Recurse -Force
 }
}
$summary=[pscustomobject]@{Engine=$PSVersionTable.PSVersion.ToString();Passed=$script:passed;Boundary='Simulated registry; real isolated file and ACL fixtures; no live Windows settings changed.'}
if($ResultPath){$summary|ConvertTo-Json|Set-Content -LiteralPath $ResultPath -Encoding UTF8}
$summary|Format-List
