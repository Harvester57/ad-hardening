# [REQ-DC-155] Prohibit Access to Windows Connect Now Wizards on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now`
    * **Policy**: `Prohibit access of the Windows Connect Now wizards` -> **Enabled**
  * **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI`
    * `DisableWcnUi` = `1` (REG_DWORD)

---

## Rationale
The Windows Connect Now (WCN) wizards guide users through configuring a wireless router or access point and saving network configuration settings to USB flash memory or broadcasting them via Wi-Fi.

On Tier 0 Domain Controllers:
1. **Administrative Interface Lockdown**: Interactive administrative sessions on Domain Controllers must never expose consumer wireless or hardware configuration wizards that could be inadvertently or maliciously invoked.
2. **Prevent Unauthorized Configuration Storage**: WCN wizards allow exporting wireless network keys and connection settings to removable storage or across the network. Prohibiting access to the WCN wizards (`DisableWcnUi = 1`) ensures the GUI wizard interface cannot be launched.

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Domain Controllers are dedicated servers with no requirement for interactive wireless provisioning wizards.
* **Administrative Sessions**: Administrators connecting via console or RDP Restricted Admin Mode will not be able to launch WCN wizards, maintaining standard operational baseline compliance.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now`
4. Configure the policy:
   * **Setting**: `Prohibit access of the Windows Connect Now wizards`
   * **State**: **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to prohibit access to WCN wizards on the Domain Controller.

[Download Script: Configure-ProhibitWcnWizards.ps1](../implementation_scripts/Configure-ProhibitWcnWizards.ps1)

```powershell
# Configure-ProhibitWcnWizards.ps1
# Description: Prohibits access to Windows Connect Now wizards on Domain Controllers.

Write-Host "Prohibiting access to Windows Connect Now wizards..." -ForegroundColor Cyan

$WcnUiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
if (-not (Test-Path -Path $WcnUiPath)) {
    New-Item -Path $WcnUiPath -Force | Out-Null
}

Set-ItemProperty -Path $WcnUiPath -Name "DisableWcnUi" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Windows Connect Now wizards prohibited successfully (DisableWcnUi = 1)." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-ProhibitWcnWizardsStatus.ps1](../audit_scripts/Get-ProhibitWcnWizardsStatus.ps1)

```powershell
# Get-ProhibitWcnWizardsStatus.ps1
# Description: Audits registry configuration of DisableWcnUi on Domain Controllers.

Write-Host "--- Auditing DisableWcnUi Status ---" -ForegroundColor Cyan

$WcnUiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
$ExpectedValue = 1

if (Test-Path -Path $WcnUiPath) {
    $Reg = Get-ItemProperty -Path $WcnUiPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.DisableWcnUi

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] DisableWcnUi: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] DisableWcnUi: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] WCN UI Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.6.20.2 (Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled')
* **ANSSI AD Hardening Guide**: Security recommendations to restrict interactive wizards and unnecessary interfaces on Tier 0 servers.
