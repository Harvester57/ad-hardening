# [REQ-PAW-161] Account Policy: Consumer Microsoft Account Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account\Block all consumer Microsoft account user authentication`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth` = `1` (REG_DWORD)

---

## Rationale
Connecting consumer cloud identities (such as personal `@outlook.com` or `@live.com` Microsoft accounts) to administrative endpoints introduces data exfiltration vectors, shadow cloud synchronizations (OneDrive personal, Edge profile sync), and bypasses enterprise identity governance. Disabling consumer user authentication enforces enterprise-only logon pathways.

---

## Legacy Impact & Compatibility
* **Consumer Apps**: Windows Store consumer apps requiring personal Microsoft accounts will be blocked. Consumer apps have no valid operational use case on Tier 0 PAWs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account`
4. Set **Block all consumer Microsoft account user authentication** to **Enabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountBlockMsa.ps1](../implementation_scripts/Configure-PawAccountBlockMsa.ps1)

```powershell
# Configure-PawAccountBlockMsa.ps1
Write-Host "Blocking consumer Microsoft account user authentication on PAWs..." -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path $MsaPath)) { New-Item -Path $MsaPath -Force | Out-Null }
Set-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -Value 1 -Type DWord -Force

Write-Host "Consumer Microsoft account user authentication blocked." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountBlockMsaStatus.ps1](../audit_scripts/Get-PawAccountBlockMsaStatus.ps1)

```powershell
# Get-PawAccountBlockMsaStatus.ps1
Write-Host "--- Auditing PAW Consumer Microsoft Account Restrictions ---" -ForegroundColor Cyan

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
* **ANSSI AD Hardening Guide**: Recommendations on identity isolation on administrative workstations
* **DoD Windows 11 Computer STIG v2r6**: Microsoft account blocking policy
