param([Parameter(Mandatory=$true)][string]$Target,[Parameter(Mandatory=$true)][int[]]$Ports,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
$ip=$null
if(-not [Net.IPAddress]::TryParse($Target,[ref]$ip) -or $Ports.Count -gt 50 -or @($Ports|Where-Object {$_ -lt 1 -or $_ -gt 65535}).Count){throw 'IP o puertos invalidos.'}
Write-Host "Probar SOLO tu propia IP publica $Target y puertos autorizados desde OTRA conexion. No usar desde la misma LAN/VPN."
if((Read-Host 'Confirmas propiedad/autorizacion y que estas fuera de esa red? (escribir CONFIRMO)') -cne 'CONFIRMO'){return}
$results=foreach($port in ($Ports|Select-Object -Unique)){
    $client=New-Object Net.Sockets.TcpClient
    try{
        $task=$client.ConnectAsync($ip,$port)
        if($task.Wait(3000) -and $client.Connected){$status='Reachable'}else{$status='NoConnection'}
    }catch{$status='Error'}finally{$client.Dispose()}
    [pscustomobject]@{Port=$port;Status=$status}
}
$report=@{Schema='Centinela.ExternalProbe.1';Target=$Target;At=[datetime]::UtcNow.ToString('o');ConfirmedExternal=$true;Results=@($results)}
$stream=[IO.File]::Open([IO.Path]::GetFullPath($OutputPath),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 6));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
Write-Host "Informe generado: $OutputPath. NoConnection/Error no equivalen a ausencia de vulnerabilidades."
