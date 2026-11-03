param()
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if(-not $env:SystemRoot){$env:SystemRoot='C:\WINDOWS'}
$tmpBase=[IO.Path]::GetTempPath()
$pd=Join-Path $tmpBase ('pd-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $pd|Out-Null
$oldPD=$env:ProgramData;$env:ProgramData=$pd
$script:passed=0
function Assert-True($Condition,[string]$Name){if(-not $Condition){throw "FAILED: $Name"};$script:passed++;Write-Output "PASS $Name"}
function Get-Error([scriptblock]$Block){try{& $Block;return ''}catch{return $_.Exception.Message}}
try {
. (Join-Path $repo 'src/Centinela.ps1') -LibraryOnly
$id=('a'*32)
$m=Get-WorkerManifest (Join-Path $repo 'src')
Assert-True ($m.Count -eq 4 -and @($m.Values|Where-Object {$_ -notmatch '^[A-F0-9]{64}$'}).Count -eq 0) 'Manifiesto: 4 scripts con SHA256'

# --- 1. Elevacion: sin Bypass sobre la carpeta del usuario ---
$deep=Get-Content -Raw (Join-Path $repo 'src/DeepSecurity.ps1')
$start=[regex]::Match($deep,'Start-Process[^\r\n]*').Value
Assert-True ($start -match 'EncodedCommand' -and $start -notmatch 'Bypass' -and $start -notmatch "'-File'") 'Start-Process usa -EncodedCommand, sin -File ni Bypass'
$boot=New-WorkerBootstrap "C:\Users\O'Brien\Downloads\centinela\src" $id 'QUJD' $m
Assert-True ($boot.Contains("O''Brien") -and $boot -notmatch '__[A-Z]+__') 'Bootstrap: rutas escapadas y sin marcadores pendientes'
Assert-True ($boot.IndexOf('Archivo alterado') -lt $boot.IndexOf('Lock-CentinelaFolder $root') -and $boot.IndexOf('Lock-CentinelaFolder $root') -lt $boot.IndexOf('Bypass')) 'Bootstrap: verifica hashes, luego protege ProgramData y recien despues habilita scripts'
Assert-True ($boot -match 'SetAccessRuleProtection\(\$true,\$false\)' -and $boot -match "S-1-5-32-545'\),'ReadAndExecute'") 'Bootstrap: ACL sin herencia; Usuarios solo lectura'
Assert-True ((Get-Error {New-WorkerBootstrap 'C:\x' 'zz' 'QUJD' $m}) -match 'invalida') 'Bootstrap: rechaza Id invalido'
$evil=[ordered]@{'SecurityWorker.ps1'="0'+(calc)+'"}
Assert-True ((Get-Error {New-WorkerBootstrap 'C:\x' $id 'QUJD' $evil}) -match 'invalido') 'Bootstrap: rechaza manifiesto con inyeccion'
Assert-True ((Get-Error {New-WorkerBootstrap 'C:\x' $id "QUJD';calc;'" $m}) -match 'invalida') 'Bootstrap: rechaza payload con inyeccion'

# Copia alterada antes de elevar: se rechaza antes de tocar ProgramData
$src=Join-Path $tmpBase ('src-'+[guid]::NewGuid().ToString('N'));Copy-Item (Join-Path $repo 'src') $src -Recurse
Add-Content -LiteralPath (Join-Path $src 'Summary.ps1') -Value "`n# malware"
$err=Get-Error {& ([scriptblock]::Create((New-WorkerBootstrap $src $id 'QUJD' $m)))}
Assert-True ($err -match 'alterado antes de elevar: Summary.ps1') 'Bootstrap: archivo alterado se rechaza'
Assert-True (-not (Test-Path (Join-Path $pd 'Centinela'))) 'Bootstrap: no se crea ni ejecuta nada si hay alteracion'
$err=Get-Error {& ([scriptblock]::Create((New-WorkerBootstrap (Join-Path $repo 'src') $id 'QUJD' $m)))}
Write-Output "  (Linux) $err";Assert-True ($err -notmatch 'alterado') 'Bootstrap: copia intacta pasa la verificacion (el ACL real solo se prueba en Windows)'
Remove-Item -Recurse -Force (Join-Path $pd 'Centinela') -ErrorAction SilentlyContinue

# Re-verificacion del worker al iniciar
function New-Payload($Manifest){[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{Action='NetworkRead';Arguments=@{};Sid='S-1-0-0';Id=$id;Manifest=$Manifest}|ConvertTo-Json -Compress)))}
$err=Get-Error {& (Join-Path $repo 'src/SecurityWorker.ps1') -Payload (New-Payload $m)}
Assert-True ($err -match 'copia protegida') 'Worker: se niega a correr desde la carpeta del usuario'
$run=Join-Path $pd "Centinela/worker/$id";New-Item -ItemType Directory -Path $run -Force|Out-Null
foreach($f in $script:WorkerFiles){Copy-Item (Join-Path $repo "src/$f") $run}
Copy-Item (Join-Path $src 'Summary.ps1') $run -Force
$err=Get-Error {& (Join-Path $run 'SecurityWorker.ps1') -Payload (New-Payload $m)}
Assert-True ($err -match 'Archivo alterado: Summary.ps1') 'Worker: re-verifica hashes al iniciar y rechaza alteraciones'
$bad=[ordered]@{};foreach($k in $m.Keys){$bad[$k]='0'*64}
Copy-Item (Join-Path $repo 'src/Summary.ps1') $run -Force
$err=Get-Error {& (Join-Path $run 'SecurityWorker.ps1') -Payload (New-Payload $bad)}
Assert-True ($err -match 'Archivo alterado') 'Worker: manifiesto distinto se rechaza'
$err=Get-Error {& (Join-Path $run 'SecurityWorker.ps1') -Payload (New-Payload $m)}
Assert-True ($err -notmatch 'alterado|copia protegida') 'Worker: copia intacta en ProgramData pasa hashes (ACL/identidad se prueban en Windows)'

# --- 2. Resultado del worker: validacion estricta ---
$rp=Get-WorkerResultPath $id
function Set-Result($Text){[IO.File]::WriteAllText($rp,$Text)}
Set-Result (@{Schema='Centinela.WorkerResult.1';Id=$id;Action='NetworkRead';Result=@{Status='Checked';Data=@{X=1}}}|ConvertTo-Json -Depth 5)
$ok=Read-WorkerResult $rp $id 'NetworkRead'
Assert-True ($ok.Status -eq 'Checked' -and $ok.Data.X -eq 1) 'Resultado valido se acepta'
Assert-True ((Get-Error {Read-WorkerResult $rp ('b'*32) 'NetworkRead'}) -match 'formato') 'Resultado de otra solicitud (Id) se rechaza'
Assert-True ((Get-Error {Read-WorkerResult $rp $id 'BlockListener'}) -match 'formato') 'Resultado de otra accion se rechaza'
Set-Result '{"Schema":"otro","Id":"x"}';Assert-True ((Get-Error {Read-WorkerResult $rp $id 'NetworkRead'}) -match 'formato') 'Esquema desconocido se rechaza'
Set-Result 'esto no es json';Assert-True ((Get-Error {Read-WorkerResult $rp $id 'NetworkRead'}) -match 'ilegible') 'JSON invalido se rechaza'
Set-Result (@{Schema='Centinela.WorkerResult.1';Id=$id;Action='NetworkRead';Result=@{Status='$(Remove-Item C:\ -Recurse)'}}|ConvertTo-Json)
Assert-True ((Get-Error {Read-WorkerResult $rp $id 'NetworkRead'}) -match 'formato') 'Estado con codigo se rechaza y nunca se ejecuta'
Set-Result ('{"a":"'+('x'*2100000)+'"}');Assert-True ((Get-Error {Read-WorkerResult $rp $id 'NetworkRead'}) -match 'tamano') 'Resultado de mas de 2 MB se rechaza'
Set-Result '';Assert-True ((Get-Error {Read-WorkerResult $rp $id 'NetworkRead'}) -match 'tamano') 'Resultado vacio se rechaza'
$outside=Join-Path $tmpBase 'result.json';[IO.File]::WriteAllText($outside,'{}')
Assert-True ((Get-Error {Read-WorkerResult $outside $id 'NetworkRead'}) -match 'fuera') 'Resultado fuera de ProgramData\Centinela se rechaza'
Assert-True ((Get-Error {Read-WorkerResult (Join-Path $pd 'Centinela/worker/../../result.json') $id 'NetworkRead'}) -match 'fuera') 'Ruta con .. se rechaza'
Assert-True ((Get-Error {Read-WorkerResult (Get-WorkerResultPath ('c'*32)) ('c'*32) 'NetworkRead'}) -match 'Sin resultado') 'Sin archivo: error claro'
Write-Output "Passed   : $script:passed"
} finally {
    $env:ProgramData=$oldPD
    foreach($x in @($pd,$src,$outside)){if($x){Remove-Item -Recurse -Force $x -ErrorAction SilentlyContinue}}
}
