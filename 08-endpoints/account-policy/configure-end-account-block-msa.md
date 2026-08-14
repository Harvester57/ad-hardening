# [REQ-END-172] Account Policy: Consumer Microsoft Account Restrictions for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account\Block all consumer Microsoft account user authentication`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth` = `1` (REG_DWORD)

---

## Rationale
Connecting consumer cloud identities (such as personal `@outlook.com` or `@live.com` Microsoft accounts) to domain-joined endpoints creates risk of unauthorized cloud synchronization, data exfiltration via personal OneDrive shares, and unmanaged application downloads. Disabling consumer user authentication ensures that only managed Active Directory and enterprise identities can authenticate.

---

## Legacy Impact & Compatibility
* **Consumer Apps**: Windows Store apps requiring personal Microsoft consumer accounts will be blocked. Enterprise identities and managed domain logins remain unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account`
4. Set **Block all consumer Microsoft account user authentication** to **Enabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountBlockMsa.ps1](../implementation_scripts/Configure-EndAccountBlockMsa.ps1)

```powershell
# Configure-EndAccountBlockMsa.ps1
Write-Host "Blocking consumer Microsoft account user authentication on Endpoints..." -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path $MsaPath)) { New-Item -Path $MsaPath -Force | Out-Null }
Set-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -Value 1 -Type DWord -Force

Write-Host "Consumer Microsoft account user authentication blocked." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountBlockMsaStatus.ps1](../audit_scripts/Get-EndAccountBlockMsaStatus.ps1)

```powershell
# Get-EndAccountBlockMsaStatus.ps1
Write-Host "--- Auditing Endpoint Consumer Microsoft Account Restrictions ---" -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
$Val = (Get-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -ErrorAction SilentlyContinue).DisableUserAuth

if ($null -ne $Val -and $Val -eq 1) {
    Write-Host "    [+] DisableUserAuth is set to 1 (Enabled)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: DisableUserAuth is '$Val' (Expected: 1)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.9 (Microsoft Account: Block all consumer Microsoft account user authentication)
* **ANSSI AD Hardening Guide**: Recommendations on managed identity controls
* **DoD Windows 11 Computer STIG v2r6**: Microsoft account blocking policy
