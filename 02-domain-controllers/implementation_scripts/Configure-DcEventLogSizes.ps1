#Configure-DcEventLogSizes.ps1
# Description: Configures Event Log Maximum File Sizes and Retention Policies on Domain Controllers.

Write-Host "Configuring Event Log Maximum File Sizes and Retention Policies on Domain Controllers..." -ForegroundColor Cyan

# 1. Core Channels via Policy Registry Branch (values in KB)
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 131072 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 4194304 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 262144 -Type DWord -Force

# 2. Active Directory Role Channels via Service Registry Branch (values in bytes)
$RoleChannels = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service"; MaxSizeBytes = 268435456 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DNS Server"; MaxSizeBytes = 268435456 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication"; MaxSizeBytes = 134217728 }
)

foreach ($Channel in $RoleChannels) {
    if (Test-Path -Path $Channel.Path) {
        Set-ItemProperty -Path $Channel.Path -Name "Retention" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $Channel.Path -Name "MaxSize" -Value $Channel.MaxSizeBytes -Type DWord -Force
        Write-Host "  [+] Configured $($Channel.Path) MaxSize to $($Channel.MaxSizeBytes) bytes" -ForegroundColor Green
    }
}

Write-Host "[+] Domain Controller Event Log Maximum File Sizes and Retention Policies applied successfully." -ForegroundColor Green
