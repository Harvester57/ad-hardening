# [REQ-PAW-162] Account Policy: Domain Member Secure Channel Security for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal` = `1` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel` = `1` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel` = `1` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange` = `0` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge` = `30` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey` = `1` (REG_DWORD)

---

## Rationale
The Netlogon secure channel protects authentication and trust communication between domain-joined workstations and Domain Controllers:
* **Signing and Sealing (`RequireSignOrSeal`, `SealSecureChannel`, `SignSecureChannel`)**: Mandates encryption and cryptographic signing on all Netlogon RPC traffic, preventing eavesdropping and tampering.
* **Strong Session Keys (`RequireStrongKey`)**: Enforces 128-bit session keys for secure channel communication, blocking downgrade to DES or weak cipher suites (mitigating ZeroLogon and related vulnerabilities).
* **Machine Password Rotation (`DisablePasswordChange = 0`, `MaximumPasswordAge = 30`)**: Enforces automatic 30-day machine password rotation, preventing stale machine credentials from being harvested for offline persistence.

---

## Legacy Impact & Compatibility
* **Third-Party Domain Members**: Modern Windows systems natively support strong session keys and secure channel signing. No impact on supported Windows 10/11 Enterprise PAWs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Domain member: Digitally encrypt or sign secure channel data (always)**: `Enabled`
   * **Domain member: Digitally encrypt secure channel data (when possible)**: `Enabled`
   * **Domain member: Digitally sign secure channel data (when possible)**: `Enabled`
   * **Domain member: Disable machine account password changes**: `Disabled`
   * **Domain member: Maximum machine account password age**: `30` days
   * **Domain member: Require strong (Windows 2000 or later) session key**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountSecureChannel.ps1](../implementation_scripts/Configure-PawAccountSecureChannel.ps1)

```powershell
# Configure-PawAccountSecureChannel.ps1
Write-Host "Configuring PAW Domain Member Secure Channel settings..." -ForegroundColor Cyan

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path $NetlogonPath)) { New-Item -Path $NetlogonPath -Force | Out-Null }

Set-ItemProperty -Path $NetlogonPath -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SealSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SignSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "DisablePasswordChange" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "MaximumPasswordAge" -Value 30 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force

Write-Host "Domain member secure channel configurations applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountSecureChannelStatus.ps1](../audit_scripts/Get-PawAccountSecureChannelStatus.ps1)

```powershell
# Get-PawAccountSecureChannelStatus.ps1
Write-Host "--- Auditing PAW Domain Member Secure Channel Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

function Test-RegVal ($Name, $Expected) {
    $Val = (Get-ItemProperty -Path $NetlogonPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal "RequireSignOrSeal" 1
Test-RegVal "SealSecureChannel" 1
Test-RegVal "SignSecureChannel" 1
Test-RegVal "DisablePasswordChange" 0
Test-RegVal "RequireStrongKey" 1

$MaxAge = (Get-ItemProperty -Path $NetlogonPath -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue).MaximumPasswordAge
if ($null -eq $MaxAge -or $MaxAge -gt 30 -or $MaxAge -eq 0) {
    Write-Host "    [!] VULNERABLE: MaximumPasswordAge is '$MaxAge' (Expected: 30 or fewer, but not 0)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] MaximumPasswordAge: $MaxAge" -ForegroundColor Green
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.6 (Domain member secure channel options)
* **ANSSI AD Hardening Guide**: Recommendations on secure channels and machine account password rotation
* **DoD Windows 11 Computer STIG v2r6**: Domain member secure channel cryptography
