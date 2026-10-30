$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'src/Centinela.ps1'
$errors = $null; $tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
. $source -LibraryOnly
$script:passed=0
function Assert($condition,$name) {
    if (-not $condition) { throw "FAILED: $name" }
    $script:passed++; Write-Output "PASS: $name"
}
function Read-Host { param($Prompt) return $script:answer }
function Write-Host { param($Object,$ForegroundColor) }
function Write-Info { param($msg) }
function Write-Warn { param($msg) $script:warnings += $msg }
function Write-OK { param($msg) throw "Unexpected success: $msg" }
function Start-Process { throw 'Unexpected process launch' }
function Remove-MpPreference { throw 'Unexpected Defender mutation' }
function Remove-AppxPackage { throw 'Unexpected Appx mutation' }
function Remove-Item { throw 'Unexpected file deletion' }
$Global:ModoSoloLectura=$false
$script:ChangesEnabled=$true
foreach($answer in @('salir','stop','s ahora','yes','no','')) {
    $script:answer=$answer
    Assert (-not (Ask-SN 'fixture')) "Reject consent [$answer]"
}
foreach($answer in @('s','SI',' sí ')) {
    $script:answer=$answer
    Assert (Ask-SN 'fixture') "Accept exact consent [$answer]"
}
$script:answer='s'; $script:ChangesEnabled=$false
Assert (-not (Ask-SN 'fixture')) 'Candidate denies mutation even with consent'
$script:ChangesEnabled=$true; $Global:ModoSoloLectura=$true
Assert (-not (Ask-SN 'fixture')) 'Report denies mutation'
$r=Remove-BloatEntry ([pscustomobject]@{QuietUninstallString='echo fixture & echo second';UninstallString='';DisplayName='Fixture'})
Assert ($r.Status -eq 'ManualRequired' -and -not $r.Verified) 'Untrusted registry command is never executed'
$script:warnings=@()
function Get-AppxPackage { param($ErrorAction) throw 'fixture denied' }
Invoke-AuditAppsTienda
Assert (@($script:warnings -like '*no disponible*').Count -eq 1) 'Inventory failure is explicitly unavailable'
$script:calls=0
foreach($name in @('Invoke-AuditArranque','Invoke-AuditSeguridad','Invoke-AuditPrivacidad','Invoke-AuditBloatware','Invoke-LimpiezaDisco','Invoke-AuditAppsTienda')) {
    Set-Item ('Function:\'+$name) { if(-not $Global:ModoSoloLectura){throw 'Report mode lost'}; $script:calls++ }
}
Invoke-ReporteCompleto
Assert ($script:calls -eq 6 -and $Global:ModoSoloLectura) 'Report restores prior read-only state'
$launcher=[IO.File]::ReadAllText((Join-Path $root 'El Centinela de Windows.bat'))
Assert ($launcher -notmatch '(?i)getadmin|%temp%|runas|where pwsh') 'Launcher has no temporary or automatic elevation path'
Assert ($launcher.Contains('"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"')) 'Launcher uses explicit system interpreter'
$text=[IO.File]::ReadAllText($source)
Assert ($text -notmatch 'Start-Process cmd|sc.exe delete|Stop-Service wuauserv|Remove-MpPreference') 'Unsafe legacy operations removed'
Assert ($text.Contains('$script:ChangesEnabled = $false')) 'Candidate starts with mutation disabled'
Write-Output "$script:passed checks passed on $($PSVersionTable.PSVersion)"
