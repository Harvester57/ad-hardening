# Get-WinRMAndRpcHardeningStatus.ps1
# Description: Audits registry configuration of WinRM client/service options and RPC client restrictions.

Write-Host "--- Auditing WinRM and RPC Hardening Settings ---" -ForegroundColor Cyan

# 1. Audit WinRM Client
$ClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$ExpectedClient = @{
    "AllowBasic"              = 0
    "AllowUnencryptedTraffic" = 0
    "AllowDigest"             = 0
}
if (Test-Path $ClientPath) {
    $ClientReg = Get-ItemProperty -Path $ClientPath -ErrorAction SilentlyContinue
    foreach ($S in $ExpectedClient.Keys) {
        $Val = $ClientReg.$S
        $Expected = $ExpectedClient[$S]
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - WinRM Client $($S): $Val (Expected: $Expected)" -ForegroundColor $Color
    }
} else {
    Write-Host "    - WinRM Client Registry: NOT FOUND" -ForegroundColor Red
}

# 2. Audit WinRM Service
$ServicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$ExpectedService = @{
    "AllowBasic"              = 0
    "AllowUnencryptedTraffic" = 0
    "DisableRunAs"            = 1
}
if (Test-Path $ServicePath) {
    $ServiceReg = Get-ItemProperty -Path $ServicePath -ErrorAction SilentlyContinue
    foreach ($S in $ExpectedService.Keys) {
        $Val = $ServiceReg.$S
        $Expected = $ExpectedService[$S]
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - WinRM Service $($S): $Val (Expected: $Expected)" -ForegroundColor $Color
    }
} else {
    Write-Host "    - WinRM Service Registry: NOT FOUND" -ForegroundColor Red
}

# 3. Audit Windows Remote Shell
$WinRsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
if (Test-Path $WinRsPath) {
    $WinRsReg = Get-ItemProperty -Path $WinRsPath -ErrorAction SilentlyContinue
    $RsVal = $WinRsReg.AllowRemoteShellAccess
    $RsColor = if ($RsVal -eq 0) { "Green" } else { "Red" }
    Write-Host "    - Windows Remote Shell AllowRemoteShellAccess: $RsVal (Expected: 0)" -ForegroundColor $RsColor
} else {
    Write-Host "    - Windows Remote Shell Registry: NOT FOUND" -ForegroundColor Red
}

# 4. Audit RPC Clients
$RpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$RpcVal = Get-ItemProperty -Path $RpcPath -Name "RestrictRemoteClients" -ErrorAction SilentlyContinue
$RpcSetting = if ($RpcVal) { $RpcVal.RestrictRemoteClients } else { 0 }
$RpcColor = if ($RpcSetting -eq 1) { "Green" } else { "Red" }
Write-Host "    - RPC RestrictRemoteClients: $RpcSetting (Expected: 1)" -ForegroundColor $RpcColor
