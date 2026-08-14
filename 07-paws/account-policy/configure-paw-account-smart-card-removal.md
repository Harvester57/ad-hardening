# [REQ-PAW-155] Account Policy: Smart Card Removal Behavior for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Smart card removal behavior`
  * **Registry Location**:
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)

---

## Rationale
In high-security environments enforcing smart card authentication (such as YubiKeys, PIV tokens, or CAC smart cards), removing the physical hardware token must instantly lock the active desktop session (`ScRemoveOption = "1"`). This prevents unauthorized physical access if an administrator steps away from the console while leaving the device unattended.

---

## Legacy Impact & Compatibility
* **User Workflow**: Administrators must carry their smart card with them whenever leaving the PAW. Session unlocking requires re-inserting the token and supplying the hardware PIN.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Set **Interactive logon: Smart card removal behavior** to **Lock Workstation** (value `1`).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountSmartCardRemoval.ps1](../implementation_scripts/Configure-PawAccountSmartCardRemoval.ps1)

```powershell
# Configure-PawAccountSmartCardRemoval.ps1
Write-Host "Configuring PAW Smart Card removal behavior..." -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String -Force

Write-Host "Smart card removal behavior set to Lock Workstation." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountSmartCardRemovalStatus.ps1](../audit_scripts/Get-PawAccountSmartCardRemovalStatus.ps1)

```powershell
# Get-PawAccountSmartCardRemovalStatus.ps1
Write-Host "--- Auditing PAW Smart Card Removal Behavior ---" -ForegroundColor Cyan

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
* **ANSSI AD Hardening Guide**: Physical and console access restrictions on Tier 0 consoles
* **DoD Windows 11 Computer STIG v2r6**: Smart card removal policy enforcement
