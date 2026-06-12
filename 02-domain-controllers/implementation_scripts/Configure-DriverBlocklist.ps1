# Configure-DriverBlocklist.ps1
# Description: Enables the Microsoft Vulnerable Driver Blocklist in the registry and validates VBS/HVCI settings.

Write-Host "Applying hardening requirement: Enable WDAC Driver Blocklist..." -ForegroundColor Cyan

# 1. Configure the registry settings to enable the blocklist
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
$ValueName = "VulnerableDriverBlocklistEnable"

if (-not (Test-Path $RegPath)) {
    Write-Host "[+] Creating registry path: $RegPath" -ForegroundColor Gray
    New-Item -Path $RegPath -Force | Out-Null
}

Write-Host "[+] Setting registry value: $ValueName = 1" -ForegroundColor Gray
Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -ErrorAction Stop

# 2. Validate VBS / HVCI Configuration
$ScenariosPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $ScenariosPath) {
    $HvciStatus = Get-ItemProperty -Path $ScenariosPath -Name "Enabled" -ErrorAction SilentlyContinue
    if ($null -ne $HvciStatus -and $HvciStatus.Enabled -eq 1) {
        Write-Host "[+] Pre-requisite Check: Memory Integrity (HVCI) is enabled." -ForegroundColor Green
    } else {
        Write-Host "[!] Warning: Memory Integrity (HVCI) is disabled. The blocklist requires HVCI for hypervisor enforcement." -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Warning: Memory Integrity scenario configuration not found. Check VBS settings." -ForegroundColor Yellow
}

Write-Host "[+] Configuration applied successfully. A reboot is required to activate the blocklist." -ForegroundColor Green
