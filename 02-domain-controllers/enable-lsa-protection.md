# [REQ-DC-006] Enable LSA Protection

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
  * **Policy**: `Configure LSA to run as a protected process`
  * **Setting**: `Enabled` (Value: `Enabled with LSA Protection` or `1`)
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` -> `RunAsPPL` = `1` (REG_DWORD)

---

## Rationale
The Local Security Authority Subsystem Service (LSASS) process (`lsass.exe`) is responsible for enforcing security policies, handling user authentication, and storing sensitive credential secrets (such as Kerberos tickets, NT hashes, and cached credentials) in memory. Adversaries who gain local administrative rights frequently target LSASS using memory-dumping tools (e.g., Mimikatz, Procdump) to extract these credentials, leading to domain-wide compromise and lateral movement.

Enabling LSA Protection configures LSASS to run as a Protected Process Light (PPL). When running as a PPL, the operating system uses security boundaries to prevent non-protected processes (even those running with local administrator or SYSTEM privileges) from accessing LSASS memory space via debugging APIs (`OpenProcess` with read/write permissions) or injecting DLLs. This significantly increases the difficulty of offline credential harvesting.

---

## Legacy Impact & Compatibility
* **Third-Party Plug-ins**: Any third-party authentication plug-in, custom credential provider, smart card reader driver, or security agent (such as older antivirus or host-intrusion prevention systems) that interacts directly with LSASS must be digitally signed with a Microsoft signature. Unsigned binaries will fail to load into LSASS, potentially breaking multi-factor authentication or smart card logon.
* **Audit Mode**: Administrators should audit the system for unsigned LSA plug-ins before enforcing LSA Protection. Event ID 3065 and 3066 in the `Microsoft-Windows-CodeIntegrity/Operational` log will list any unsigned drivers or DLLs that would have been blocked from loading into LSASS.
* **Reboot Requirement**: Applying this setting requires a system reboot to take effect.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
4. Set the following policy:
   * **Policy**: `Configure LSA to run as a protected process`
   * **Setting**: `Enabled`
   * **Choose one of the following options**: `Enabled with LSA Protection`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

[Download Script: Configure-LSAProtection.ps1](implementation_scripts/Configure-LSAProtection.ps1)

```powershell
# Configure-LSAProtection.ps1
# Description: Enables LSA Protection (RunAsPPL) in the registry.

Write-Host "Applying hardening requirement: Enable LSA Protection..." -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "LSA Protection registry configuration applied. A reboot is required to activate." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-LSAProtectionStatus.ps1](audit_scripts/Get-LSAProtectionStatus.ps1)

```powershell
# Get-LSAProtectionStatus.ps1
# Description: Audits LSA Protection (RunAsPPL) in the registry.

Write-Host "--- Auditing LSA Protection ---" -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaReg = Get-ItemProperty -Path $regPath -Name "RunAsPPL" -ErrorAction SilentlyContinue

if ($lsaReg) {
    $pplVal = $lsaReg.RunAsPPL
    if ($pplVal -eq 1) {
        Write-Host "[+] LSA Protection is enabled. RunAsPPL is set to $($pplVal) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RunAsPPL is set to $($pplVal) (Required: 1)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: RunAsPPL registry value is missing. LSA is not running as a protected process." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R14 (LSA Protection)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.50.1 (Ensure 'Configure LSA to run as a protected process' is set to 'Enabled: Enabled with LSA Protection')
* **Microsoft Security Guidance**: Configuring Additional LSA Protection
