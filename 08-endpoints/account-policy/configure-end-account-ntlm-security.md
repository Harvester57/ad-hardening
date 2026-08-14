# [REQ-END-169] Account Policy: NTLM and LAN Manager Authentication Security for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` = `5` (REG_DWORD, Send NTLMv2 response only. Refuse LM & NTLM)
    * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec` = `537395200` (REG_DWORD, Require NTLMv2 session security, Require 128-bit encryption)
    * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec` = `537395200` (REG_DWORD, Require NTLMv2 session security, Require 128-bit encryption)
    * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback` = `0` (REG_DWORD, Allow LocalSystem NULL session fallback disabled)

---

## Rationale
Enforcing modern NTLM parameters shields endpoints from legacy protocol exploitation and relay vectors:
* **LAN Manager Compatibility Level (5)**: Restricts outbound LAN Manager authentication exclusively to NTLMv2, rejecting LM and NTLMv1 negotiations.
* **128-bit Session Security (`NTLMMinClientSec` / `NTLMMinServerSec`)**: Mandates 128-bit encryption and NTLMv2 session security for all NTLM SSP connections, preventing downgrade to weak legacy session keys.
* **NULL Session Fallback Block (`allownullsessionfallback`)**: Prevents services running as LocalSystem from dropping to unauthenticated anonymous sessions if Kerberos or NTLM fails.

---

## Legacy Impact & Compatibility
* **Legacy Devices**: Legacy systems and multi-function printers unable to authenticate using NTLMv2 with 128-bit session security will fail authentication. Such devices should be modernized.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Network security: LAN Manager authentication level**: `Send NTLMv2 response only. Refuse LM & NTLM` (value `5`)
   * **Network security: Minimum session security for NTLM SSP based (including secure RPC) clients**: `Require NTLMv2 session security, Require 128-bit encryption` (value `537395200`)
   * **Network security: Minimum session security for NTLM SSP based (including secure RPC) servers**: `Require NTLMv2 session security, Require 128-bit encryption` (value `537395200`)
   * **Network security: Allow LocalSystem NULL session fallback**: `Disabled` (value `0`)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountNtlmSecurity.ps1](../implementation_scripts/Configure-EndAccountNtlmSecurity.ps1)

```powershell
# Configure-EndAccountNtlmSecurity.ps1
Write-Host "Configuring Endpoint NTLM and LAN Manager authentication security..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }
Set-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force

$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
if (-not (Test-Path $MsvPath)) { New-Item -Path $MsvPath -Force | Out-Null }
Set-ItemProperty -Path $MsvPath -Name "NTLMMinClientSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path $MsvPath -Name "NTLMMinServerSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path $MsvPath -Name "allownullsessionfallback" -Value 0 -Type DWord -Force

Write-Host "NTLM and LAN Manager authentication security applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountNtlmSecurityStatus.ps1](../audit_scripts/Get-EndAccountNtlmSecurityStatus.ps1)

```powershell
# Get-EndAccountNtlmSecurityStatus.ps1
Write-Host "--- Auditing Endpoint NTLM and LAN Manager Security ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"

function Test-RegVal ($Path, $Name, $Expected) {
    $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name under $Path is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal $LsaPath "LmCompatibilityLevel" 5
Test-RegVal $MsvPath "NTLMMinClientSec" 537395200
Test-RegVal $MsvPath "NTLMMinServerSec" 537395200
Test-RegVal $MsvPath "allownullsessionfallback" 0

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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.11.2 (LmCompatibilityLevel), Section 2.3.11.7 (NTLMMinClientSec), Section 2.3.11.8 (NTLMMinServerSec), Section 2.3.11.10 (allownullsessionfallback)
* **ANSSI AD Hardening Guide**: Recommendations on NTLM deprecation and NTLMv2 enforcement
* **DoD Windows 11 Computer STIG v2r6**: LAN Manager authentication parameters
