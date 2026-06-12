# Get-CredentialGuardStatus.ps1
# Description: Audits the configuration and operational status of Credential Guard.

Write-Host "--- Auditing Credential Guard ---" -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit Registry Settings
$vbsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$lsaReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

$ExpectedVbsSettings = @{
    "EnableVirtualizationBasedSecurity" = 1
    "HVCIMATRequired"                   = 1
    "ConfigureSystemGuardLaunch"        = 1
    "RequirePlatformSecurityFeatures"   = 1
    "HypervisorEnforcedCodeIntegrity"   = 1
}

if (Test-Path $vbsRegPath) {
    $vbsValues = Get-ItemProperty -Path $vbsRegPath -ErrorAction SilentlyContinue
    foreach ($Setting in $ExpectedVbsSettings.Keys) {
        $Val = $vbsValues.$Setting
        $Expected = $ExpectedVbsSettings[$Setting]
        if ($Val -eq $Expected) {
            Write-Host "[+] VBS setting '$Setting' is correctly configured ($Val)." -ForegroundColor Green
        } else {
            Write-Host "[!] VULNERABLE: VBS setting '$Setting' is missing or incorrect ($Val)." -ForegroundColor Red
            $vulnerable = $true
        }
    }
} else {
    Write-Host "[!] VULNERABLE: Virtualization-Based Security registry path does not exist." -ForegroundColor Red
    $vulnerable = $true
}

if ($lsaReg -and ($lsaReg.LsaCfgFlags -eq 1 -or $lsaReg.LsaCfgFlags -eq 2)) {
    Write-Host "[+] Credential Guard registry key is configured (LsaCfgFlags = $($lsaReg.LsaCfgFlags))." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Credential Guard registry key 'LsaCfgFlags' is missing or set to 0." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit WMI Operational State (if running)
$deviceGuard = Get-CimInstance -Namespace "root\cimv2" -ClassName "Win32_DeviceGuard" -ErrorAction SilentlyContinue
if ($deviceGuard) {
    # SecurityServicesConfigured: 1 = Credential Guard
    $servicesConfigured = $deviceGuard.SecurityServicesConfigured
    # SecurityServicesRunning: 1 = Credential Guard
    $servicesRunning = $deviceGuard.SecurityServicesRunning
    
    $cgConfigured = $false
    $cgRunning = $false
    
    foreach ($service in $servicesConfigured) {
        if ($service -eq 1) { $cgConfigured = $true }
    }
    foreach ($service in $servicesRunning) {
        if ($service -eq 1) { $cgRunning = $true }
    }
    
    if ($cgConfigured) {
        Write-Host "[+] Credential Guard is configured operationally." -ForegroundColor Green
    } else {
        Write-Host "[-] Credential Guard is not configured in WMI (requires reboot/hardware compatibility)." -ForegroundColor Yellow
    }
    
    if ($cgRunning) {
        Write-Host "[+] Credential Guard is running." -ForegroundColor Green
    } else {
        Write-Host "[-] Credential Guard is not running in WMI (requires reboot/hardware compatibility)." -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] WMI class Win32_DeviceGuard is not available (common on older OS or without Hyper-V features installed)." -ForegroundColor Yellow
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE (Registry configurations missing)" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE (Registry configurations applied)" -ForegroundColor Green
}
