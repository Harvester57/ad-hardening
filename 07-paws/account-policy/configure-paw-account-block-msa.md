# [REQ-PAW-161] Account Policy: Consumer Microsoft Account Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Microsoft Account
* **Policy Setting**: Block all consumer Microsoft account user authentication: `Enabled`
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Key & Value**:
  * `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth` = `1` (REG_DWORD, Blocks consumer Microsoft account authentication)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1567.002: Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/), [T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

---

## Rationale

Privileged Access Workstations serve as the dedicated management plane for Active Directory Domain Controllers, Tier 0 PKI, and identity federation infrastructure. Introducing consumer cloud identities into this trusted boundary creates critical security exposures:

### Technical Threat Vectors and Defense Mechanics
1. **Preventing Shadow Cloud Data Exfiltration**:
   Personal Microsoft Accounts (such as `@outlook.com`, `@hotmail.com`, or personal Microsoft 365 accounts) natively integrate with consumer cloud services (personal OneDrive, Microsoft Edge personal profile sync, Windows backup). When an administrator signs in or links a consumer account, operating system artifacts—including clipboard history, browser credentials, personal file vaults, and Wi-Fi profiles—can automatically synchronize to external consumer cloud storage. Setting `DisableUserAuth = 1` prohibits Windows from authenticating or connecting consumer Microsoft Accounts, completely eliminating this unauthorized exfiltration channel.
2. **Enforcing Strict Identity Boundary Separation**:
   Tier 0 administration demands that only dedicated administrative directory accounts (managed within the on-premises AD forest or dedicated Entra ID tenant) are used. Consumer accounts lack multi-factor authentication enforcement governed by enterprise Conditional Access, fail corporate auditing and logging requirements, and cannot be revoked by enterprise identity administrators.
3. **Closing App-Level Consumer Single Sign-On (SSO)**:
   In modern Windows versions, consumer Microsoft Accounts can be leveraged by universal Windows platform (UWP) applications and modern store packages for authentication. Disabling consumer account user authentication terminates the background Web Account Manager (WAM) broker from facilitating consumer authentication flows, preventing background token issuance.
4. **Defense-in-Depth Comparison (PAW vs Endpoint)**:
   While standard client endpoints must also block consumer accounts to satisfy enterprise DLP requirements, on PAWs this restriction is non-negotiable. PAW hardware and sessions must remain hermetically sealed from any non-administrative consumer identity services.

---

## Legacy Impact & Compatibility

* **Consumer Applications and Services**: Built-in Windows consumer applications (such as Xbox app, personal Microsoft Store, consumer OneDrive client) that require personal account sign-in will fail to authenticate with error codes indicating that administrator policies block consumer accounts. These applications have no legitimate operational purpose on Tier 0 PAWs and should be uninstalled or restricted.
* **Enterprise Accounts Unaffected**: Enterprise Active Directory domain logons, smart card / PIN authentication, and enterprise Entra ID work/school accounts (`@company.com`) are unaffected by this setting.
* **Pre-requisites**: Ensure that administrative workflows do not rely on personal accounts for downloading administrative tooling. All administrative packages must be distributed via enterprise repositories or approved internal file shares.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Account`
4. Double-click **Block all consumer Microsoft account user authentication**.
5. Set the policy to **Enabled**.
6. Click **Apply**, then **OK**.
7. Link the GPO to the dedicated PAW OU and verify policy propagation.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountBlockMsa.ps1](../implementation_scripts/Configure-PawAccountBlockMsa.ps1)

```powershell
# Configure-PawAccountBlockMsa.ps1
# Description: Blocks consumer Microsoft account user authentication on PAWs.

Write-Host "Blocking consumer Microsoft account user authentication on PAWs..." -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path -Path $MsaPath)) {
    New-Item -Path $MsaPath -Force | Out-Null
}
Set-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -Value 1 -Type DWord -Force

Write-Host "Consumer Microsoft account user authentication blocked successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountBlockMsaStatus.ps1](../audit_scripts/Get-PawAccountBlockMsaStatus.ps1)

```powershell
# Get-PawAccountBlockMsaStatus.ps1
# Description: Audits consumer Microsoft account blocking status on PAWs.

Write-Host "--- Auditing PAW Consumer Microsoft Account Restrictions ---" -ForegroundColor Cyan

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
Confirm that the value `DisableUserAuth` is of type `REG_DWORD` and set to `0x1`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.9.15.1 (Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.9.15.1 (Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled')
* **DoD Windows 11 Computer STIG**: Rule SV-220803r879703_rule (Blocking consumer Microsoft accounts)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (PAW Isolation and Elimination of Unmanaged Cloud Identities)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Microsoft Account Policies
* **Related Controls**: [REQ-END-172: Account Policy: Consumer Microsoft Account Restrictions for Endpoints](../../08-endpoints/account-policy/configure-end-account-block-msa.md), [REQ-PAW-160: Account Policy: Windows Hello for Business and PIN Complexity for PAWs](configure-paw-account-hello-pin.md)
