$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'Solo ejecutar en runner descartable de GitHub Actions.'}
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Centinela.ps1') -LibraryOnly
if(-not (Test-IsAdmin)){throw 'El runner necesita administrador para la prueba de firewall.'}
$bad=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{Action='NetworkRead';Arguments=@{};Sid='S-1-0-0';Id=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)))
$denied=$false
try{& (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/SecurityWorker.ps1') -Payload $bad}catch{$denied=$true}
if(-not $denied){throw 'El helper no rechazo otra identidad.'}
Write-Output 'PASS native wrong-SID request rejected before action'
$read=Invoke-ElevatedSecurity 'NetworkRead' @{}
if($read.Status -ne 'Checked' -or -not $read.Data){throw 'El helper nativo no devolvio inventario de red.'}
Write-Output 'PASS native worker serialization, same-SID validation and network inventory'
$base=Join-Path $env:ProgramData 'Centinela\worker'
$acl=Get-Acl -LiteralPath $base
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Carpeta del worker con propietario no administrador.'}
if(-not $acl.AreAccessRulesProtected){throw 'La carpeta del worker hereda permisos.'}
foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.AccessControlType -eq 'Allow' -and ([int]$r.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership') -and $r.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw "ACE escribible: $($r.IdentityReference.Value)"}}
Write-Output 'PASS native ProgramData worker folder owned by Administrators, no inheritance, read-only for users'
$copy=Join-Path $env:TEMP ('centinela-tamper-'+[guid]::NewGuid().ToString('N'));Copy-Item (Join-Path (Split-Path $PSScriptRoot -Parent) 'src') $copy -Recurse
$manifest=Get-WorkerManifest $copy;Add-Content -LiteralPath (Join-Path $copy 'DeepSecurity.ps1') -Value '# tamper'
$refused=$false;try{& ([scriptblock]::Create((New-WorkerBootstrap $copy ([guid]::NewGuid().ToString('N')) 'QUJD' $manifest)))}catch{$refused=$_.Exception.Message -match 'alterado'}
Remove-Item -Recurse -Force $copy
if(-not $refused){throw 'El bootstrap no rechazo un script alterado.'}
Write-Output 'PASS native bootstrap refuses scripts modified after hashing'
$listener=New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback),0
$rule=$null
try {
    $listener.Start()
    $port=$listener.LocalEndpoint.Port
    $process=Get-Process -Id $PID
    $result=Invoke-ElevatedSecurity 'BlockListener' @{Port=$port;ProcessId=$PID;Program=$process.Path}
    if($result.Status -ne 'RuleVerified'){throw ($result|ConvertTo-Json -Compress)}
    $rule=$result.Rule
    $effective=Get-NetFirewallRule -Name $rule -PolicyStore ActiveStore -ErrorAction Stop
    if([string]$effective.Action -ne 'Block'){throw 'Regla efectiva no encontrada.'}
    Write-Output 'PASS native journal-before-rule, scoped firewall creation and ActiveStore verification'
    $undo=Invoke-ElevatedSecurity 'UndoBlock' @{Rule=$rule}
    if($undo.Status -ne 'Verified' -or (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue)){throw 'No se verifico eliminacion de regla.'}
    $rule=$null
    Write-Output 'PASS native typed undo and absence verification'
} finally {
    $listener.Stop()
    if($rule -and $rule -match '^Centinela-[a-f0-9]{32}$'){Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue}
}
Write-Output 'Only disposable runner modified. No updates installed; no public listener created; actual UAC consent prompt not tested.'
