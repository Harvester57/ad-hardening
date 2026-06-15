# Configure-PrintingAndSpooler.ps1
# Description: Hardens Windows Print Spooler settings, RPC configurations, and Point and Print policies.

Write-Host "Applying Print Spooler security hardening..." -ForegroundColor Cyan

# 1. Base Printers Path Policies
$PrintersPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
if (-not (Test-Path $PrintersPath)) {
    New-Item -Path $PrintersPath -Force | Out-Null
}

# Allow Print Spooler to accept client connections -> Disabled
Set-ItemProperty -Path $PrintersPath -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type Dword
Set-ItemProperty -Path $PrintersPath -Name "RegisterSpoolerRemoteSubsystem" -Value 0 -Type Dword

# Configure Redirection Guard -> Enabled: Redirection Guard Enabled
Set-ItemProperty -Path $PrintersPath -Name "RedirectionguardPolicy" -Value 1 -Type Dword

# Manage processing of Queue-specific files -> Enabled: Limit Queue-specific files to Color profiles
Set-ItemProperty -Path $PrintersPath -Name "CopyFilesPolicy" -Value 1 -Type Dword

# 2. Printers RPC Connection and Listener Policies
$PrintersRpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
if (-not (Test-Path $PrintersRpcPath)) {
    New-Item -Path $PrintersRpcPath -Force | Out-Null
}

# Protocol to use for outgoing RPC connections -> RPC over TCP (0)
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcUseNamedPipeProtocol" -Value 0 -Type Dword

# Use authentication for outgoing RPC connections -> Default (0)
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcAuthentication" -Value 0 -Type Dword

# Protocols to allow for incoming RPC connections -> RPC over TCP (5)
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcProtocols" -Value 5 -Type Dword

# Authentication protocol to use for incoming RPC connections -> Negotiate (0)
Set-ItemProperty -Path $PrintersRpcPath -Name "ForceKerberosForRpc" -Value 0 -Type Dword

# Configure RPC over TCP port -> 0
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcTcpPort" -Value 0 -Type Dword

# 3. System Print Control Privacy Setting
$PrintControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
if (-not (Test-Path $PrintControlPath)) {
    New-Item -Path $PrintControlPath -Force | Out-Null
}

# Configure RPC packet level privacy setting for incoming connections -> Enabled
Set-ItemProperty -Path $PrintControlPath -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -Type Dword

# 4. Point and Print Restrictions
$PointPrintPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $PointPrintPath)) {
    New-Item -Path $PointPrintPath -Force | Out-Null
}

Set-ItemProperty -Path $PointPrintPath -Name "RestrictPointAndPrint" -Value 1 -Type Dword
Set-ItemProperty -Path $PointPrintPath -Name "NoWarningNoElevationOnInstall" -Value 0 -Type Dword
Set-ItemProperty -Path $PointPrintPath -Name "UpdatePromptSettings" -Value 0 -Type Dword

Write-Host "[+] Print Spooler and Printer configurations hardened successfully." -ForegroundColor Green
