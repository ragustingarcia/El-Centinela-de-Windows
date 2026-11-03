$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'Solo ejecutar en runner descartable de GitHub Actions.'}
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Centinela.ps1') -LibraryOnly
if(-not (Test-IsAdmin)){throw 'El runner necesita administrador para la prueba de firewall.'}
$read=Invoke-ElevatedSecurity 'NetworkRead' @{}
if($read.Status -ne 'Checked' -or -not $read.Data){throw 'El helper nativo no devolvio inventario de red.'}
Write-Output 'PASS native worker serialization, same-SID validation and network inventory'
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
