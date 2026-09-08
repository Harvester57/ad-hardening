# Configure-SvchostMitigation.ps1
# Description: Configures svchost.exe mitigation options to enforce Microsoft-signed binaries and block dynamic code.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "Applying hardening requirement: Configure svchost.exe mitigation options..." -ForegroundColor Cyan

# Verify minimum operating system build compatibility (Windows 10 1903 / Build 18362 or Windows Server 2022 / Build 20348)
$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build

if ($osBuild -lt 18362) {
    Write-Warning "The operating system build ($($osBuild)) does not support EnableSvchostMitigationPolicy (requires Windows 10 1903+ or Windows Server 2022+)."
    exit 1
}

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ValueData = 1

try {
    if (-not (Test-Path -Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Host "Created registry key: $($RegPath)" -ForegroundColor Gray
    }

    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force | Out-Null

    # Validate written value
    $configuredValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ($configuredValue -eq $ValueData) {
        Write-Host "Hardening applied successfully: $($ValueName) set to 1." -ForegroundColor Green
        Write-Host "Note: This policy applies to newly created svchost.exe instances. A full system restart is required to protect services initialized at system boot." -ForegroundColor Yellow
        exit 0
    } else {
        throw "Failed to verify registry property value after write."
    }
} catch {
    Write-Error "Error configuring svchost.exe mitigation options: $($_.Exception.Message)"
    exit 1
}
