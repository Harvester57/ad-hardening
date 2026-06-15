# Get-CredentialGuardStatus.ps1
# Description: Audits the configuration and operational status of VBS and ensures Credential Guard is disabled.

Write-Host "--- Auditing VBS and Credential Guard Status ---" -ForegroundColor Cyan
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

# For DCs, Credential Guard (LsaCfgFlags) must be set to 0 (Disabled)
if ($null -ne $lsaReg -and $lsaReg.LsaCfgFlags -ne 0) {
    Write-Host "[!] VULNERABLE: Credential Guard is enabled in registry (LsaCfgFlags = $($lsaReg.LsaCfgFlags))." -ForegroundColor Red
    $vulnerable = $true
} else {
    $val = if ($null -eq $lsaReg) { "Not configured (Disabled)" } else { $lsaReg.LsaCfgFlags }
    Write-Host "[+] Credential Guard registry key 'LsaCfgFlags' is correctly set to disabled ($val)." -ForegroundColor Green
}

# 2. Audit WMI Operational State (if running)
$deviceGuard = Get-CimInstance -Namespace "root\cimv2" -ClassName "Win32_DeviceGuard" -ErrorAction SilentlyContinue
if ($deviceGuard) {
    # SecurityServicesRunning: 1 = Credential Guard
    $servicesRunning = $deviceGuard.SecurityServicesRunning
    $cgRunning = $false
    foreach ($service in $servicesRunning) {
        if ($service -eq 1) { $cgRunning = $true }
    }
    
    if ($cgRunning) {
        Write-Host "[!] VULNERABLE: Credential Guard is running operationally on this Domain Controller." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] Credential Guard is not running on this Domain Controller." -ForegroundColor Green
    }
} else {
    Write-Host "[-] WMI class Win32_DeviceGuard is not available." -ForegroundColor Yellow
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE (Credential Guard enabled or VBS misconfigured)" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE (Credential Guard disabled and VBS configured)" -ForegroundColor Green
}
