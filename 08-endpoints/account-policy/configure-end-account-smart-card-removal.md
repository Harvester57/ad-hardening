# [REQ-END-166] Account Policy: Smart Card Removal Behavior for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Smart card removal behavior`
  * **Registry Location**:
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)

---

## Rationale
In environments using smart card or hardware token authentication, removing the physical token must immediately lock the active user session (`ScRemoveOption = "1"`). This prevents unauthorized physical access to unattended workstations if a user leaves the device without manually locking the console.

---

## Legacy Impact & Compatibility
* **User Workflow**: Users authenticating via smart cards must carry their token with them, which automatically locks the session. Re-authenticating requires inserting the card and entering the PIN.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Set **Interactive logon: Smart card removal behavior** to **Lock Workstation** (value `1`).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountSmartCardRemoval.ps1](../implementation_scripts/Configure-EndAccountSmartCardRemoval.ps1)

```powershell
# Configure-EndAccountSmartCardRemoval.ps1
Write-Host "Configuring Endpoint Smart Card removal behavior..." -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String -Force

Write-Host "Smart card removal behavior set to Lock Workstation." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountSmartCardRemovalStatus.ps1](../audit_scripts/Get-EndAccountSmartCardRemovalStatus.ps1)

```powershell
# Get-EndAccountSmartCardRemovalStatus.ps1
Write-Host "--- Auditing Endpoint Smart Card Removal Behavior ---" -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$Val = (Get-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -ErrorAction SilentlyContinue).ScRemoveOption

if ($Val -eq "1") {
    Write-Host "    [+] ScRemoveOption is set to '$Val' (Lock Workstation)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: ScRemoveOption is set to '$Val' (Expected: '1')" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.9.5 (Interactive logon: Smart card removal behavior)
* **ANSSI AD Hardening Guide**: Recommendations on session locking and multi-factor hardware tokens
* **DoD Windows 11 Computer STIG v2r6**: Smart card removal behavior policy
