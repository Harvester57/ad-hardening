# [REQ-END-168] Account Policy: Local Accounts and Blank Password Restrictions for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

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
Restricting local account permissions and blocking weak legacy password hashes limits lateral movement and credential harvesting:
* **Blank Passwords Limit (`LimitBlankPasswordUse`)**: Restricting accounts with empty passwords to console-only logons prevents remote attackers from authenticating across network shares, RDP, or WinRM using blank credentials.
* **No LM Hash (`NoLMHash`)**: Disables the generation and caching of weak LAN Manager hashes upon password updates.
* **Sharing Model (`ForceNetworkLogon`)**: Enforces the Classic security model where network logons authenticate using the caller's actual identity rather than Guest.

---

## Legacy Impact & Compatibility
* **Empty Password Accounts**: Accounts without passwords cannot be used for remote access or network resource sharing.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Accounts: Limit local account use of blank passwords to console logon only**: `Enabled`
   * **Network security: Do not store LAN Manager hash value on next password change**: `Enabled`
   * **Network access: Sharing and security model for local accounts**: `Classic - local users authenticate as themselves`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountLocalBlankPasswords.ps1](../implementation_scripts/Configure-EndAccountLocalBlankPasswords.ps1)

```powershell
# Configure-EndAccountLocalBlankPasswords.ps1
Write-Host "Configuring Endpoint local account and blank password restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }

Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ForceNetworkLogon" -Value 0 -Type DWord -Force

Write-Host "Local account and blank password restrictions applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountLocalBlankPasswordsStatus.ps1](../audit_scripts/Get-EndAccountLocalBlankPasswordsStatus.ps1)

```powershell
# Get-EndAccountLocalBlankPasswordsStatus.ps1
Write-Host "--- Auditing Endpoint Local Account and Blank Password Restrictions ---" -ForegroundColor Cyan
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
* **ANSSI AD Hardening Guide**: Recommendations on local account security and LAN Manager hashes
* **DoD Windows 11 Computer STIG v2r6**: Blank password use restrictions
