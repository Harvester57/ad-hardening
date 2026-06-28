# [REQ-DC-030] Secure Directory Services Restore Mode (DSRM) and Recovery Parameters

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0).
* **Operating Systems**: Windows Server 2016, 2019, 2022, 2025.

---

## Implementation Details
* **Priority**: High (Reduces offline DC attack surface).
* **GPO Path / Registry Location**:
  * Registry Path: `HKLM\System\CurrentControlSet\Control\Lsa`
  * Value Name: `DsrmAdminLogonBehavior`
  * Value Type: `REG_DWORD`
  * Value Data: `1` (Allows DSRM Admin logon only when booted in DSRM).

---

## Rationale
Directory Services Restore Mode (DSRM) is a special boot mode for Domain Controllers that allows administrators to repair or restore the Active Directory database (NTDS.dit). DSRM uses a local Administrator account separate from the AD directory.

If DSRM is not secured:
1. **Network Authentication Abuse**: By default, or if misconfigured (e.g. `DsrmAdminLogonBehavior` set to `0` or `2`), the local DSRM administrator account can authenticate over the network to the Domain Controller. Since this account has a static password (often never changed since DC promotion), it can be targeted for brute-forcing, pass-the-hash, or DCSync credential retrieval.
2. **Offline Recovery Attacks**: If the DC is booted in Safe Mode/DSRM, local controls are reduced.

Setting `DsrmAdminLogonBehavior` to `1` ensures the DSRM Administrator account can only log on locally, and only when the DC is booted into DSRM mode. Setting it to `2` allows logon when the AD service is stopped, which is also a risk.

---

## Legacy Impact & Compatibility
* **Offline Recovery Access**: To use DSRM for database maintenance, administrators must have physical console access (or out-of-band console access like iDRAC/iLO/Hyper-V console) since remote RDP or network logons will be rejected.
* **Credential Synchronization**: The DSRM password must be rotated periodically and synchronized with a highly secure Domain Admin credential.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Create or edit a GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create a new **Registry Item** with the following properties:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `System\CurrentControlSet\Control\Lsa`
   * **Value Name**: `DsrmAdminLogonBehavior`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `00000001` (Hexadecimal)
5. Deploy and link the GPO to enforce the registry setting domain-wide.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

To automate verification and local remediation of the DSRM configuration:

[Download Script: Set-DsrmHardening.ps1](implementation_scripts/Set-DsrmHardening.ps1)

```powershell
# Set-DsrmHardening.ps1
# Description: Configures DsrmAdminLogonBehavior to restrict network logons.

$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DsrmAdminLogonBehavior"
$ValueData = 1 # Restrict network logons

Write-Host "Applying hardening: Restricting DSRM Admin Logon Behavior..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord
Write-Host "[+] Registry parameter set successfully: $ValueName = $ValueData" -ForegroundColor Green

# Instructions for DSRM password sync
Write-Host "`n[NOTE] Ensure that you synchronize the DSRM Administrator password with the Domain Administrator account." -ForegroundColor Yellow
Write-Host "Run the following command to sync passwords:" -ForegroundColor Yellow
Write-Host "  ntdsutil `"set dsrm password`" `"sync from domain account administrator`" q q" -ForegroundColor Yellow
```

*To verify the DSRM configuration status:*

[Download Script: Get-DsrmHardeningStatus.ps1](audit_scripts/Get-DsrmHardeningStatus.ps1)

```powershell
# Get-DsrmHardeningStatus.ps1
# Check if DsrmAdminLogonBehavior registry parameter is set to 1.

$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DsrmAdminLogonBehavior"

if (-not (Test-Path $RegPath)) {
    Write-Host "[!] NON-COMPLIANT: Registry key '$RegPath' does not exist." -ForegroundColor Red
    exit 1
}

$Value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $Value -or $Value.$ValueName -ne 1) {
    Write-Host "[!] NON-COMPLIANT: DSRM network logon is not restricted (DsrmAdminLogonBehavior is not 1)." -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] COMPLIANT: DSRM network logon is restricted (DsrmAdminLogonBehavior = 1)." -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R14 (Harden directory services restore mode (DSRM))
* **CIS Benchmark**: Section 2.3.1.2 (LSA Security Settings)
* **PingCastle Rule**: `P-RecoveryModeUnprotected` (Ensure the \"automatic administrative logon\" feature of the recovery mode is not enabled)
