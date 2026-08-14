# [REQ-PAW-157] Account Policy: Local Accounts and Blank Password Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse` = `1` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash` = `1` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Control\Lsa\ForceNetworkLogon` = `0` (REG_DWORD, Classic sharing model)

---

## Rationale
Restricting local accounts and blocking unauthenticated or weakly authenticated interactions mitigates privilege escalation and credential compromise:
* **Blank Passwords Limit (`LimitBlankPasswordUse`)**: Restricting blank passwords strictly to physical console logons prevents local accounts with empty passwords from authenticating remotely across network shares, WinRM, or RDP.
* **No LM Hash (`NoLMHash`)**: Disables the generation and storage of legacy, easily crackable LAN Manager password hashes in the SAM and directory databases upon password modifications.
* **Sharing Model (`ForceNetworkLogon`)**: Enforces the Classic security model where incoming network connections authenticate as the actual local user rather than collapsing into the Guest account.

---

## Legacy Impact & Compatibility
* **Empty Password Accounts**: Any service or user account without a password cannot connect remotely. Strong passwords must be assigned to all accounts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Accounts: Limit local account use of blank passwords to console logon only**: `Enabled`
   * **Network security: Do not store LAN Manager hash value on next password change**: `Enabled`
   * **Network access: Sharing and security model for local accounts**: `Classic - local users authenticate as themselves`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountLocalBlankPasswords.ps1](../implementation_scripts/Configure-PawAccountLocalBlankPasswords.ps1)

```powershell
# Configure-PawAccountLocalBlankPasswords.ps1
Write-Host "Configuring PAW local account and blank password restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }

Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ForceNetworkLogon" -Value 0 -Type DWord -Force

Write-Host "Local account and blank password restrictions applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountLocalBlankPasswordsStatus.ps1](../audit_scripts/Get-PawAccountLocalBlankPasswordsStatus.ps1)

```powershell
# Get-PawAccountLocalBlankPasswordsStatus.ps1
Write-Host "--- Auditing PAW Local Account and Blank Password Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

function Test-RegVal ($Name, $Expected) {
    $Val = (Get-ItemProperty -Path $LsaPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal "LimitBlankPasswordUse" 1
Test-RegVal "NoLMHash" 1
Test-RegVal "ForceNetworkLogon" 0

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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.7.3 (LimitBlankPasswordUse), Section 2.3.11.4 (NoLMHash), Section 2.3.10.12 (ForceNetworkLogon)
* **ANSSI AD Hardening Guide**: Recommendations on LAN Manager hashes and local account protections
* **DoD Windows 11 Computer STIG v2r6**: Blank password use restrictions
