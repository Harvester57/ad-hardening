# Get-DcWshStatus.ps1
# Description: Audits Windows Script Host registry state across 64-bit and 32-bit hives and script file extension association handlers on Domain Controllers.

Write-Host "--- Auditing Windows Script Host Hardening on Domain Controllers ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit WSH Registry settings in 64-bit HKLM
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (Test-Path $RegistryHklm) {
    $ValHklm = (Get-ItemProperty -Path $RegistryHklm -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($ValHklm -eq 0) {
        Write-Host "    - HKLM WSH Enabled: 0 (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: HKLM WSH is enabled or not configured (Value: '$($ValHklm)')" -ForegroundColor Red
        $script:Vulnerable = $true
    }

    $TrustHklm = (Get-ItemProperty -Path $RegistryHklm -Name "TrustPolicy" -ErrorAction SilentlyContinue).TrustPolicy
    if ($TrustHklm -eq 2) {
        Write-Host "    - HKLM WSH TrustPolicy: 2 (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: HKLM WSH TrustPolicy is not set to 2 (Value: '$($TrustHklm)')" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - VULNERABLE: HKLM WSH settings key is missing (Expected: Enabled = 0, TrustPolicy = 2)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit WSH Registry settings in WOW6432Node on 64-bit systems
if ([Environment]::Is64BitOperatingSystem) {
    $RegistryWow64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings"
    if (Test-Path $RegistryWow64) {
        $ValWow64 = (Get-ItemProperty -Path $RegistryWow64 -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        if ($ValWow64 -eq 0) {
            Write-Host "    - WOW6432Node WSH Enabled: 0 (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: WOW6432Node WSH is enabled or not configured (Value: '$($ValWow64)')" -ForegroundColor Red
            $script:Vulnerable = $true
        }

        $TrustWow64 = (Get-ItemProperty -Path $RegistryWow64 -Name "TrustPolicy" -ErrorAction SilentlyContinue).TrustPolicy
        if ($TrustWow64 -eq 2) {
            Write-Host "    - WOW6432Node WSH TrustPolicy: 2 (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: WOW6432Node WSH TrustPolicy is not set to 2 (Value: '$($TrustWow64)')" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: WOW6432Node WSH settings key is missing (Expected: Enabled = 0, TrustPolicy = 2)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 3. Audit file associations
$Extensions = @("vbs", "vbe", "js", "jse", "wsf", "wsh", "hta")
foreach ($Ext in $Extensions) {
    $ProgIdPath = "HKLM:\SOFTWARE\Classes\.$Ext"
    if (Test-Path $ProgIdPath) {
        $Handler = (Get-ItemProperty -Path $ProgIdPath -Name "" -ErrorAction SilentlyContinue).""
        if ($Handler -eq "txtfile" -or $Handler -match "notepad") {
            Write-Host "    - Extension .$Ext Handler: $Handler (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: Extension .$Ext Handler is '$($Handler)' (Expected: txtfile/notepad)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: Extension .$Ext Class Registry key not found." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "[-] Audit Result: VULNERABLE - Windows Script Host hardening controls on Domain Controller do not meet baseline requirements." -ForegroundColor Red
} else {
    Write-Host "[+] Audit Result: SECURE - Windows Script Host hardening controls on Domain Controller are fully compliant." -ForegroundColor Green
}
