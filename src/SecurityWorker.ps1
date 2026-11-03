param([Parameter(Mandatory=$true)][string]$Payload)
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
. (Join-Path $PSScriptRoot 'Centinela.ps1') -LibraryOnly
if($Payload.Length -gt 16384){throw 'Solicitud demasiado grande.'}
$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))|ConvertFrom-Json
if($request.Action -isnot [string] -or $request.Arguments -isnot [pscustomobject] -or $request.Id -notmatch '^[a-f0-9]{32}$' -or $request.Sid -ne (Get-Identity) -or -not (Test-IsAdmin)){throw 'Identidad, permiso o solicitud invalida. Usar la misma cuenta al elevar.'}
$path=Join-Path (Get-StateFolder) ('worker-'+$request.Id+'.json')
try { switch($request.Action){
    'NetworkRead' {$result=@{Status='Checked';Data=(Get-NetworkInvestigation)}}
    {$_ -in @('EnableRealtime','UpdateSignatures','QuickScan')} {$result=Invoke-SecuritySolution $request.Action}
    'InstallSecurityUpdates' {$result=Install-SelectedSecurityUpdates $request.Arguments.Ids}
    'BlockListener' {$result=Block-VerifiedListener ([int]$request.Arguments.Port) ([int]$request.Arguments.ProcessId) ([string]$request.Arguments.Program)}
    'UndoBlock' {Undo-ListenerBlock $request.Arguments.Rule;$result=@{Status='Verified';Detail='Regla de bloqueo eliminada.'}}
    'IsolatePython' {
        $exe=Get-KnownPython;$name='Centinela-IOC-'+[guid]::NewGuid().ToString('N')
        New-NetFirewallRule -Name $name -DisplayName 'Centinela IOC: aislamiento temporal de Python' -Direction Outbound -Action Block -Program $exe -Profile Any -ErrorAction Stop|Out-Null
        $rule=Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
        $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        if([string]$rule.Enabled -ne 'True' -or @($profiles|Where-Object {[string]$_.Enabled -ne 'True'}).Count){Remove-NetFirewallRule -Name $name;throw 'Firewall efectivo no permite verificar aislamiento.'}
        $result=@{Status='Verified';Rule=$name;Program=$exe;Detail='Bloqueo saliente para este python.exe en perfiles activos. Puede afectar otras sesiones Python; no es una sandbox completa de todos los subprocesos del sistema.'}
    }
    'UndoIsolation' {
        if($request.Arguments.Rule -notmatch '^Centinela-IOC-[a-f0-9]{32}$'){throw 'Regla invalida.'}
        Remove-NetFirewallRule -Name $request.Arguments.Rule -ErrorAction Stop
        if(Get-NetFirewallRule -Name $request.Arguments.Rule -ErrorAction SilentlyContinue){throw 'Regla aun presente.'}
        $result=@{Status='Verified';Detail='Aislamiento temporal retirado.'}
    }
    default {throw 'Accion no permitida.'}
}
Save-Journal $result $path
} catch {
    if($name -and $name -match '^Centinela-IOC-[a-f0-9]{32}$'){Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue}
    Save-Journal @{Action=$request.Action;Status='Failed';Detail=$_.Exception.Message} $path
}
