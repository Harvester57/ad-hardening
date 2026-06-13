# [REQ-PAW-002] Enable LSA Protection for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Policies\Administrative Templates\System\Local Security Authority\Configure LSASS to run as a protected process
  * **Registry Location**: HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    * `RunAsPPL` = `1` (REG_DWORD)

---

## Rationale
The Local Security Authority Subsystem Service (LSASS) process manages security policies, user authentication, and credential tokens on Windows systems. Attackers targeting administrative workstations commonly attempt to extract plain-text credentials or NT hashes from LSASS memory using debugging tools (e.g., Mimikatz, Procdump).

Enabling LSA Protection ensures that:
1. **Protected Process Light (PPL)**: The LSASS process runs as a Protected Process Light (PPL).
2. **Access Restriction**: Only verified, digitally signed code can load into LSASS, and standard processes (even those running as local system/administrator) cannot read the memory space of LSASS or inject code into it.
3. **Mitigating Dump Attacks**: Credential harvesting tools cannot dump LSASS memory to disk or scrape keys from LSA memory blocks.

---

## Legacy Impact & Compatibility
* **Driver Signing**: Any custom authentication packages or third-party smart card drivers that load into LSASS must be digitally signed with a Microsoft signature. Unsigned drivers will be blocked from loading.
* **Reboot Required**: Enabling or disabling LSA Protection requires a system restart to take effect.
* **Audit Mode Available**: LSA Protection can be run in audit mode (using registry value `AuditLevel` under the Lsa key) to test for unsigned driver compatibility prior to full enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the PAWs Organizational Unit (OU) (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
4. Configure the setting:
   * **Policy**: `Configure LSASS to run as a protected process`
   * **Setting**: `Enabled`
   * **Configure LSA to run as a protected process**: `Enabled with UEFI Lock` (or `Enabled without UEFI Lock` depending on management needs)
5. Link the GPO to the PAWs Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the local registry key on the PAW to run LSASS as a protected process.

[Download Script: Configure-PawLsaProtection.ps1](implementation_scripts/Configure-PawLsaProtection.ps1)

```powershell
# Configure-PawLsaProtection.ps1
# Description: Configures the RunAsPPL registry key to enable LSA Protection on PAWs.

Write-Host "Applying LSA Protection registry hardening..." -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}

Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "[+] LSA Protection (RunAsPPL) enabled in registry. (Reboot required)." -ForegroundColor Green
```

*To verify the local LSA Protection state:*

[Download Script: Test-PawLsaProtection.ps1](audit_scripts/Test-PawLsaProtection.ps1)

```powershell
# Test-PawLsaProtection.ps1
# Description: Checks the registry settings and running process state to verify LSA Protection is active.

Write-Host "--- Auditing LSA Protection Status ---" -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$RunAsPPL = (Get-ItemProperty -Path $LsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

if ($RunAsPPL -eq 1) {
    Write-Host "    - LSA Protection (RunAsPPL): Enabled (Secure)" -ForegroundColor Green
} else {
    Write-Host "    - VULNERABLE: LSA Protection (RunAsPPL) is not configured or disabled (Value: $($RunAsPPL))" -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on administrative workstation protection and LSASS security.
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.2.1 (LSA Protection)
* **Microsoft Security Baselines**: Windows Defender Credential Guard and LSA Protection guidelines.
