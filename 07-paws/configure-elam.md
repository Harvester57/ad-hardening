# [REQ-PAW-014] Configure Early Launch Antimalware (ELAM) Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations.
* **Operating Systems**: Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **ELAM GPO**: `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy` -> Enabled (Select **Good, unknown and bad but critical** in options)
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch` -> `DriverLoadPolicy` = `3` (REG_DWORD)

---

## Rationale
Privileged Access Workstations (PAWs) require the highest level of boot integrity to prevent compromise of Tier 0 administrative tasks:

1. **Early Boot Rootkits**: Malicious boot-start drivers can execute before third-party endpoint protection or security agents initialize. Enforcing the Early Launch Antimalware (ELAM) driver initialization policy ensures that unknown, unsigned, or bad drivers are prevented from loading at boot time.
2. **Platform Integrity**: Securing the boot sequence with ELAM is a critical requirement of Virtualization-Based Security (VBS) and overall hardware-rooted protection.

---

## Legacy Impact & Compatibility
* **Boot-Start Drivers**: If third-party, custom, or legacy hardware monitoring drivers are unsigned, the ELAM policy will block them from loading, potentially resulting in blue screen (BSOD) or hardware failures. Verify all active drivers possess valid digital signatures prior to enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO applied to your PAWs (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware`
4. Double-click **Boot-Start Driver Initialization Policy**.
5. Set it to **Enabled**.
6. In the options dropdown, select **Good, unknown and bad but critical** (registry value `3`).
7. Click **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply the ELAM driver load policy.

[Download Script: Configure-ElamPolicy.ps1](implementation_scripts/Configure-ElamPolicy.ps1)

```powershell
# Configure-ElamPolicy.ps1
# Description: Configures the Early Launch Antimalware (ELAM) boot-start driver load policy on the local system.

Write-Host "Applying ELAM Boot-Start driver initialization policy..." -ForegroundColor Cyan

$ElamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $ElamPath)) {
    New-Item -Path $ElamPath -Force | Out-Null
}
Set-ItemProperty -Path $ElamPath -Name "DriverLoadPolicy" -Value 3 -Type DWord -ErrorAction Stop
Write-Host "[+] ELAM Boot-Start driver initialization policy set to Good, unknown and bad but critical." -ForegroundColor Green
```

*To audit the ELAM driver load policy status:*

[Download Script: Get-ElamPolicyStatus.ps1](audit_scripts/Get-ElamPolicyStatus.ps1)

```powershell
# Get-ElamPolicyStatus.ps1
# Description: Audits registry configuration of the Early Launch Antimalware (ELAM) policy.

Write-Host "--- Auditing ELAM Boot-Start Policy ---" -ForegroundColor Cyan

$script:Vulnerable = $false

$Path = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$Name = "DriverLoadPolicy"
$Expected = 3

if (Test-Path $Path) {
    $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $Val = $Reg.$Name
    if ($Val -eq $Expected) {
        Write-Host "  [+] Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Green
    } else {
        Write-Host "  [!] MISMATCH: Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] NOT FOUND: Path $($Path) (Expected: $Name = $Expected)" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark - Section 18.2.2 (System Options / ELAM)
* **ANSSI AD Hardening Guide**: Section addressing system and boot configuration integrity.
