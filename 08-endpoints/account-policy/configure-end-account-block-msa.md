# [REQ-END-172] Account Policy: Consumer Microsoft Account Restrictions for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Microsoft Account
* **Policy Setting**: Block all consumer Microsoft account user authentication: `Enabled`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Key & Value**:
  * `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth` = `1` (REG_DWORD, Blocks consumer Microsoft account authentication)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1567.002: Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/), [T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

---

## Rationale

Allowing users to attach consumer Microsoft Accounts (such as `@outlook.com`, `@hotmail.com`, or `@live.com`) to enterprise-managed client workstations bypasses corporate identity perimeters and exposes organizational data to unauthorized external storage:

### Technical Threat Vectors and Defense Mechanics
1. **Mitigating Data Loss and Shadow Cloud Sync**:
   When consumer accounts are added to Windows endpoints, the operating system activates consumer cloud synchronization features, including personal OneDrive synchronization, Edge browser history and password syncing, and Windows backup to consumer storage. Corporate data, passwords, and sensitive documents can be silently uploaded to personal consumer cloud repositories, violating corporate data loss prevention (DLP) and regulatory compliance standards. Configuring `DisableUserAuth = 1` stops Windows from authenticating or registering consumer accounts.
2. **Preventing Shadow IT and Rogue App Installs**:
   Consumer account authentication allows users to access the consumer Windows Store to download unvetted consumer applications, games, or utilities. Blocking consumer accounts prevents the operating system's Web Account Manager (WAM) from obtaining consumer tokens, preventing unapproved software installations and license confusion.
3. **Preserving Enterprise Identity Governance**:
   Corporate assets should be accessed exclusively via enterprise-managed credentials (on-premises Active Directory domain accounts or enterprise Entra ID work accounts). Enterprise accounts can be subjected to conditional access policies, session monitoring, immediate revocation, and compliance auditing. Personal Microsoft Accounts are entirely outside IT governance and cannot be audited or revoked by enterprise administrators upon employee departure.
4. **Endpoint vs PAW Considerations**:
   On Tier 2 endpoints, blocking consumer accounts prevents accidental data leakage by everyday business users while maintaining enterprise single sign-on (SSO) for authorized corporate cloud services. On PAWs, this control is reinforced to prevent any cross-tier contamination between administrative duties and external identities.

---

## Legacy Impact & Compatibility

* **Consumer Applications**: Personal Microsoft Store apps, personal OneDrive clients, and Xbox identity integrations will be unable to sign in. Users attempting to connect personal accounts will receive a notification that the action is blocked by organization policy.
* **Corporate Identities Unaffected**: Domain user logons, smart card PINs, and enterprise Microsoft Entra ID work accounts (`@company.com`) are fully supported and function normally.
* **Rollout Recommendations**: Communicate the policy change to end users so they understand that corporate endpoints are reserved strictly for organizational business activities and corporate identities.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Account`
4. Double-click **Block all consumer Microsoft account user authentication**.
5. Set the policy to **Enabled**.
6. Click **Apply**, then **OK**.
7. Link the GPO to the target workstation Organizational Units (OUs).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountBlockMsa.ps1](../implementation_scripts/Configure-EndAccountBlockMsa.ps1)

```powershell
# Configure-EndAccountBlockMsa.ps1
# Description: Blocks consumer Microsoft account user authentication on Endpoints.

Write-Host "Blocking consumer Microsoft account user authentication on Endpoints..." -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path -Path $MsaPath)) {
    New-Item -Path $MsaPath -Force | Out-Null
}
Set-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -Value 1 -Type DWord -Force

Write-Host "Consumer Microsoft account user authentication blocked successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountBlockMsaStatus.ps1](../audit_scripts/Get-EndAccountBlockMsaStatus.ps1)

```powershell
# Get-EndAccountBlockMsaStatus.ps1
# Description: Audits consumer Microsoft account blocking status on Endpoints.

Write-Host "--- Auditing Endpoint Consumer Microsoft Account Restrictions ---" -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"

if (-not (Test-Path -Path $MsaPath)) {
    Write-Host "    [!] MISSING KEY: $MsaPath" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}

$Val = (Get-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -ErrorAction SilentlyContinue).DisableUserAuth

if ($null -ne $Val -and $Val -eq 1) {
    Write-Host "    [+] DisableUserAuth is set to 1 (Enabled - Secure)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: DisableUserAuth is '$Val' (Expected: 1)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
```

---

### Option C: Manual Verification

Verify the applied policy via command prompt using `reg query`:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount" /v DisableUserAuth
```
Confirm that `DisableUserAuth` exists with a value of `0x1`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.9.15.1 (Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.9.15.1 (Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled')
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 18.9.15.1 (Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled')
* **DoD Windows 11 Computer STIG**: Rule SV-220803r879703_rule (Blocking consumer Microsoft accounts)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Identity Perimeter Isolation)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Microsoft Account Policies
* **Related Controls**: [REQ-PAW-161: Account Policy: Consumer Microsoft Account Restrictions for PAWs](../../07-paws/account-policy/configure-paw-account-block-msa.md), [REQ-END-171: Account Policy: Windows Hello for Business and PIN Complexity for Endpoints](configure-end-account-hello-pin.md)
