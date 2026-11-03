param([Parameter(Mandatory=$true)][string]$Payload)
$ErrorActionPreference='Stop'
$env:PSModulePath=[IO.Path]::Combine($env:SystemRoot,'System32\WindowsPowerShell\v1.0\Modules')
if($Payload.Length -gt 16384){throw 'Solicitud demasiado grande.'}
$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))|ConvertFrom-Json
if($request.Id -notmatch '^[a-f0-9]{32}$' -or $null -eq $request.Manifest){throw 'Solicitud invalida.'}
# Re-verificacion al iniciar (antes de cargar cualquier otro script): ubicacion protegida, hashes y permisos.
$expected=[IO.Path]::GetFullPath((Join-Path (Join-Path (Join-Path $env:ProgramData 'Centinela') 'worker') $request.Id))
if([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\','/') -ne $expected.TrimEnd('\','/')){throw 'El ayudante elevado solo corre desde su copia protegida en ProgramData.'}
$sha=[Security.Cryptography.SHA256]::Create()
foreach($name in @('SecurityWorker.ps1','Centinela.ps1','Summary.ps1','DeepSecurity.ps1')){
    $want=[string]$request.Manifest.$name
    $got=-join($sha.ComputeHash([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)))|ForEach-Object {$_.ToString('X2')})
    if($want -notmatch '^[A-F0-9]{64}$' -or $got -ne $want){throw "Archivo alterado: $name. No se ejecuto nada."}
}
$trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$acl=Get-Acl -LiteralPath $PSScriptRoot
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'Carpeta del ayudante con propietario no confiable.'}
$writeMask=[int]([Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership,DeleteSubdirectoriesAndFiles')
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.AccessControlType -eq 'Allow' -and ([int]$rule.FileSystemRights -band $writeMask) -and $rule.IdentityReference.Value -notin $trusted){throw 'Carpeta del ayudante escribible por cuentas no administradoras.'}
}
. (Join-Path $PSScriptRoot 'Centinela.ps1') -LibraryOnly
if($request.Action -isnot [string] -or $request.Arguments -isnot [pscustomobject] -or $request.Sid -ne (Get-Identity) -or -not (Test-IsAdmin)){throw 'Identidad, permiso o solicitud invalida. Usar la misma cuenta al elevar.'}
$path=Join-Path $PSScriptRoot 'result.json'
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
Save-Journal @{Schema='Centinela.WorkerResult.1';Id=$request.Id;Action=$request.Action;Result=$result} $path
} catch {
    if($name -and $name -match '^Centinela-IOC-[a-f0-9]{32}$'){Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue}
    Save-Journal @{Schema='Centinela.WorkerResult.1';Id=$request.Id;Action=$request.Action;Result=@{Action=$request.Action;Status='Failed';Detail=$_.Exception.Message}} $path
}
