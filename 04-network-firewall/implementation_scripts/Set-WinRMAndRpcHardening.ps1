# Set-WinRMAndRpcHardening.ps1
# Description: Hardens WinRM client/service parameters and restricts remote RPC clients.

Write-Host "Applying WinRM and RPC channel hardening settings..." -ForegroundColor Cyan

# 1. WinRM Client Hardening
$ClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if (-not (Test-Path $ClientPath)) {
    New-Item -Path $ClientPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientPath -Name "AllowBasic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ClientPath -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ClientPath -Name "AllowDigest" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] WinRM Client parameters hardened." -ForegroundColor Green

# 2. WinRM Service Hardening
$ServicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
if (-not (Test-Path $ServicePath)) {
    New-Item -Path $ServicePath -Force | Out-Null
}
Set-ItemProperty -Path $ServicePath -Name "AllowBasic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ServicePath -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ServicePath -Name "DisableRunAs" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] WinRM Service parameters hardened." -ForegroundColor Green

# 3. Windows Remote Shell Hardening
$WinRsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
if (-not (Test-Path $WinRsPath)) {
    New-Item -Path $WinRsPath -Force | Out-Null
}
Set-ItemProperty -Path $WinRsPath -Name "AllowRemoteShellAccess" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Windows Remote Shell access disabled." -ForegroundColor Green

# 4. RPC Client Restrictions
$RpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
if (-not (Test-Path $RpcPath)) {
    New-Item -Path $RpcPath -Force | Out-Null
}
Set-ItemProperty -Path $RpcPath -Name "RestrictRemoteClients" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Unauthenticated RPC client restrictions enforced (RestrictRemoteClients = 1)." -ForegroundColor Green
