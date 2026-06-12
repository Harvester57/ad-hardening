# Hardening Requirement: Restrict Remote SAM API Access

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10 (1607+), Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Network access: Restrict clients allowed to make remote calls to SAM`
  * **Setting**: `O:BAG:BAD:(A;;RC;;;BA)` (Security Descriptor definition in SDDL format, which grants Remote Access/Read Control only to the built-in Administrators group - BA)
  * **Registry Location**: `HKLM\System\CurrentControlSet\Control\Lsa` -> `RestrictRemoteSAM` = `O:BAG:BAD:(A;;RC;;;BA)` (REG_SZ)

---

## Rationale
By default, the Security Account Manager (SAM) and NT Directory Services (NTDS) allow remote RPC connections from non-privileged accounts. Using these connections, an attacker who has established a foothold in the network (even with a basic, non-administrative domain user account) can query the Domain Controller or member servers to enumerate local users, group memberships, and security policies.

Tools like BloodHound/SharpHound, or simple commands like `net user /domain`, rely on these remote SAM RPC interfaces to extract information for network profiling and lateral movement mapping. Restricting remote client access to the SAM API (utilizing `RestrictRemoteSAM`) ensures that only members of the built-in Administrators group can make remote RPC queries. This significantly reduces the recon capabilities of an internal attacker.

---

## Legacy Impact & Compatibility
* **Monitoring Tool Impact**: Monitoring, configuration management, vulnerability scanning, or security audit systems that run under non-administrative accounts and remotely query local user or group lists on servers will fail. These tools must be updated to run under administrative credentials, or their service accounts must be explicitly granted access in the custom SDDL security descriptor.
* **Compatibility Testing**: Prior to wide-scale enforcement, check the `System` event log on Domain Controllers for event sources relating to SAM RPC blocks (Event ID 16962 and 16969, which log blocked remote calls to SAM with details on the calling user account and IP).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Network access: Restrict clients allowed to make remote calls to SAM`
   * **Setting**: Click **Edit Security** and configure the permissions. By default, only local Administrators are granted access. Ensure the SDDL translates to `O:BAG:BAD:(A;;RC;;;BA)`.
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

[Download Script: Configure-RestrictRemoteSAM.ps1](implementation_scripts/Configure-RestrictRemoteSAM.ps1)

```powershell
# Configure-RestrictRemoteSAM.ps1
# Description: Restricts remote RPC access to the SAM database to local Administrators.

Write-Host "Applying hardening requirement: Restrict Remote SAM API Access..." -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$sddl = "O:BAG:BAD:(A;;RC;;;BA)"
Set-ItemProperty -Path $regPath -Name "RestrictRemoteSAM" -Value $sddl -Type String
Write-Host "SAM remote API access restricted to Administrators (SDDL applied)." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-RestrictRemoteSAMStatus.ps1](audit_scripts/Get-RestrictRemoteSAMStatus.ps1)

```powershell
# Get-RestrictRemoteSAMStatus.ps1
# Description: Audits the RestrictRemoteSAM registry value.

Write-Host "--- Auditing RestrictRemoteSAM ---" -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$lsaReg = Get-ItemProperty -Path $regPath -Name "RestrictRemoteSAM" -ErrorAction SilentlyContinue

if ($lsaReg) {
    $sddlVal = $lsaReg.RestrictRemoteSAM
    if ($sddlVal -eq "O:BAG:BAD:(A;;RC;;;BA)") {
        Write-Host "[+] Remote SAM access is secure. RestrictRemoteSAM matches expected SDDL: $($sddlVal)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictRemoteSAM is configured but has a different SDDL: $($sddlVal) (Expected: O:BAG:BAD:(A;;RC;;;BA))." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: RestrictRemoteSAM registry key is missing. System allows remote SAM enumeration by standard users." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R4 (Minimization of service execution and interface exposures)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.10.10 (Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allowed')
* **Microsoft Security Guidance**: Network access: Restrict clients allowed to make remote calls to SAM configuration
