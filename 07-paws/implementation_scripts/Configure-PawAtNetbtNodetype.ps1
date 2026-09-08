#Configure-PawAtNetbtNodetype.ps1
# Description: Configures Administrative Templates: Configure NetBT Node Type and Name Release for PAWs.

Write-Host "Configuring Administrative Templates: Configure NetBT Node Type and Name Release for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure NetBT Node Type and Name Release for PAWs applied successfully." -ForegroundColor Green
