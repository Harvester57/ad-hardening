# [REQ-END-173] Account Policy: Domain Member Secure Channel Security for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

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
The Netlogon secure channel protects domain communication between member endpoints and Domain Controllers:
* **Signing and Sealing (`RequireSignOrSeal`, `SealSecureChannel`, `SignSecureChannel`)**: Mandates encryption and cryptographic signing on all Netlogon RPC traffic, preventing man-in-the-middle eavesdropping and tampering.
* **Strong Session Keys (`RequireStrongKey`)**: Enforces 128-bit session keys for secure channel communication, blocking downgrade to DES or weak ciphers.
* **Machine Password Rotation (`DisablePasswordChange = 0`, `MaximumPasswordAge = 30`)**: Enforces automatic 30-day computer account password rotation, ensuring dormant machine accounts cannot be compromised for persistence.

---

## Legacy Impact & Compatibility
* **Third-Party Domain Members**: Modern Windows systems natively support strong session keys and secure channel signing.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
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

[Download Script: Configure-EndAccountSecureChannel.ps1](../implementation_scripts/Configure-EndAccountSecureChannel.ps1)

```powershell
# Configure-EndAccountSecureChannel.ps1
Write-Host "Configuring Endpoint Domain Member Secure Channel settings..." -ForegroundColor Cyan

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

[Download Script: Get-EndAccountSecureChannelStatus.ps1](../audit_scripts/Get-EndAccountSecureChannelStatus.ps1)

```powershell
# Get-EndAccountSecureChannelStatus.ps1
Write-Host "--- Auditing Endpoint Domain Member Secure Channel Settings ---" -ForegroundColor Cyan
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
