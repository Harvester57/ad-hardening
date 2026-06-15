# Configure-DCSecurityOptions.ps1
# Description: Configures GPO Security Options registry keys for Domain Controllers.

Write-Host "Applying hardening requirement: Configure Security Options for Domain Controllers..." -ForegroundColor Cyan

# 1. Domain controller: Allow server operators to schedule tasks = Disabled (SubmitQueue = 0)
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "SubmitQueue" -Value 0 -Type DWord -Force
Write-Host "    Domain controller: Allow server operators to schedule tasks set to Disabled." -ForegroundColor Green

# 2. Domain controller: Allow vulnerable Netlogon secure channel connections = Not Configured / Explicitly Blocked
$NetlogonParamsPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path $NetlogonParamsPath)) {
    New-Item -Path $NetlogonParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $NetlogonParamsPath -Name "AllowVulnerableChannel" -Value 0 -Type DWord -Force
Write-Host "    Domain controller: Allow vulnerable Netlogon connections set to Disabled." -ForegroundColor Green

# 3. Domain controller: Refuse machine account password changes = Disabled
Set-ItemProperty -Path $NetlogonParamsPath -Name "RefusePasswordChange" -Value 0 -Type DWord -Force
Write-Host "    Domain controller: Refuse machine account password changes set to Disabled." -ForegroundColor Green

# 4. Domain member: Disable machine account password changes = Disabled
Set-ItemProperty -Path $NetlogonParamsPath -Name "DisablePasswordChange" -Value 0 -Type DWord -Force
Write-Host "    Domain member: Disable machine account password changes set to Disabled." -ForegroundColor Green

# 5. Domain member: Maximum machine account password age = 30
Set-ItemProperty -Path $NetlogonParamsPath -Name "MaximumPasswordAge" -Value 30 -Type DWord -Force
Write-Host "    Domain member: Maximum machine account password age set to 30." -ForegroundColor Green

# 6. Domain member: Require strong (Windows 2000 or later) session key = Enabled
Set-ItemProperty -Path $NetlogonParamsPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force
Write-Host "    Domain member: Require strong session key set to Enabled." -ForegroundColor Green

# 7. Network access: Named Pipes that can be accessed anonymously (netlogon, samr, lsarpc)
$LanmanServerParamsPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $LanmanServerParamsPath)) {
    New-Item -Path $LanmanServerParamsPath -Force | Out-Null
}
$NullSessionPipes = @("netlogon", "samr", "lsarpc")
Set-ItemProperty -Path $LanmanServerParamsPath -Name "NullSessionPipes" -Value $NullSessionPipes -Type MultiString -Force
Write-Host "    Network access: Named Pipes that can be accessed anonymously configured." -ForegroundColor Green

# 8. Network access: Remotely accessible registry paths
$WinregExactPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths"
if (-not (Test-Path $WinregExactPath)) {
    New-Item -Path $WinregExactPath -Force | Out-Null
}
$AllowedExactPaths = @(
    "System\CurrentControlSet\Control\ProductOptions",
    "System\CurrentControlSet\Control\Server Applications",
    "Software\Microsoft\Windows NT\CurrentVersion"
)
Set-ItemProperty -Path $WinregExactPath -Name "Machine" -Value $AllowedExactPaths -Type MultiString -Force
Write-Host "    Network access: Remotely accessible registry paths configured." -ForegroundColor Green

# 9. Network access: Remotely accessible registry paths and sub-paths
$WinregPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths"
if (-not (Test-Path $WinregPath)) {
    New-Item -Path $WinregPath -Force | Out-Null
}
$AllowedPaths = @(
    "System\CurrentControlSet\Control\Print\Printers",
    "System\CurrentControlSet\Services\Eventlog",
    "Software\Microsoft\OLAP Server",
    "Software\Microsoft\Windows NT\CurrentVersion\Print",
    "Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "System\CurrentControlSet\Control\ContentIndex",
    "System\CurrentControlSet\Control\Terminal Server",
    "System\CurrentControlSet\Control\Terminal Server\UserConfig",
    "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
    "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
    "System\CurrentControlSet\Services\SysmonLog"
)

# Optional AD CS or WINS sub-paths
$CertSvc = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
if ($null -ne $CertSvc) {
    $AllowedPaths += "System\CurrentControlSet\Services\CertSvc"
    Write-Host "    AD CS detected: adding CertSvc registry path." -ForegroundColor Gray
}
$WinsSvc = Get-Service -Name "WINS" -ErrorAction SilentlyContinue
if ($null -ne $WinsSvc) {
    $AllowedPaths += "System\CurrentControlSet\Services\WINS"
    Write-Host "    WINS detected: adding WINS registry path." -ForegroundColor Gray
}

Set-ItemProperty -Path $WinregPath -Name "Machine" -Value $AllowedPaths -Type MultiString -Force
Write-Host "    Network access: Remotely accessible registry paths and sub-paths configured." -ForegroundColor Green

Write-Host "Domain Controller Security Options configuration completed." -ForegroundColor Green
