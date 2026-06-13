# [REQ-ID-002] Enable Local Administrator Password Solution (LAPS)

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\System\LAPS`
  * **Policies**:
    * `Configure password backup directory`: `Enabled` (Set to `Active Directory`)
    * `Password Settings`: `Enabled` (Set Password Complexity to `Large letters + small letters + numbers + special characters`, Password Length to `20` characters, and Password Age to `30` days)
    * `Enable local admin password management`: `Enabled`
  * **Registry Location**: `HKLM\Software\Policies\Microsoft\Windows\LAPS`
    * `BackupDirectory` = `1` (REG_DWORD, Active Directory)
    * `PasswordComplexity` = `4` (REG_DWORD, 4 = Large + small + numbers + special characters)
    * `PasswordLength` = `20` (REG_DWORD)
    * `PasswordAgeDays` = `30` (REG_DWORD)

---

## Rationale
In standard Active Directory setups, local administrator accounts on member servers and client workstations often share the same password. If a single machine is compromised and the local administrator password hash is extracted (e.g., from LSASS memory or SAM database), attackers can leverage Pass-the-Hash (PtH) techniques to log on to other domain machines laterally.

Implementing the Local Administrator Password Solution (LAPS) completely mitigates this lateral movement vector by automatically generating a unique, complex password for the specified local administrator account on each machine. These passwords are changed periodically and stored securely in a confidential attribute (`msLAPS-Password` or `ms-Mcs-AdmPwd`) on the computer's Active Directory object. Read access is restricted to authorized administrative groups.

---

## Legacy Impact & Compatibility
* **LAPS Client Dependency**: Devices must have the Windows LAPS extension installed (native to modern Windows updates) or have the Classic LAPS client installed.
* **Schema Extension**: The Active Directory schema must be extended to include LAPS attributes.
* **AD Permissions**: Ensure permissions on computer objects are configured to block non-administrator users from reading the confidential password attributes.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_MemberServers`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\LAPS`
4. Configure the following settings:
   * **Policy**: `Configure password backup directory`
     * **Setting**: `Enabled`
     * **Options**: Set backup directory to `Active Directory`.
   * **Policy**: `Password Settings`
     * **Setting**: `Enabled`
     * **Options**: Set complexity to `Large letters + small letters + numbers + special characters`, length to `20`, and age to `30` days.
   * **Policy**: `Enable local admin password management`
     * **Setting**: `Enabled`
5. Link the GPO to the Organizational Units (OUs) containing member servers and client workstations.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to configure Windows LAPS locally using the registry.

[Download Script: Configure-LAPS.ps1](implementation_scripts/Configure-LAPS.ps1)

```powershell
# Configure-LAPS.ps1
# Description: Configures Windows LAPS parameters in the registry.

Write-Host "Applying hardening requirement: Enable Local Administrator Password Solution..." -ForegroundColor Cyan

$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\LAPS"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# 1 = Backup to Active Directory
Set-ItemProperty -Path $RegPath -Name "BackupDirectory" -Value 1 -Type DWord
# 4 = Letters + numbers + special characters
Set-ItemProperty -Path $RegPath -Name "PasswordComplexity" -Value 4 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordLength" -Value 20 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -Value 30 -Type DWord

Write-Host "Windows LAPS configuration registry settings applied successfully." -ForegroundColor Green
```

*To verify LAPS configuration settings locally:*
[Download Script: Get-LAPSStatus.ps1](audit_scripts/Get-LAPSStatus.ps1)

```powershell
# Get-LAPSStatus.ps1
# Description: Checks the Windows LAPS registry parameters.

Write-Host "--- Auditing LAPS Registry Configuration ---" -ForegroundColor Cyan

$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\LAPS"

if (Test-Path $RegPath) {
    $backupDir = Get-ItemProperty -Path $RegPath -Name "BackupDirectory" -ErrorAction SilentlyContinue
    $complexity = Get-ItemProperty -Path $RegPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue
    $length = Get-ItemProperty -Path $RegPath -Name "PasswordLength" -ErrorAction SilentlyContinue
    $age = Get-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -ErrorAction SilentlyContinue
    
    Write-Host "[+] LAPS Configuration Found:" -ForegroundColor Green
    Write-Host "    - Backup Directory: $($backupDir.BackupDirectory) (1 = Active Directory)" -ForegroundColor White
    Write-Host "    - Password Complexity: $($complexity.PasswordComplexity) (4 = Maximum)" -ForegroundColor White
    Write-Host "    - Password Length: $($length.PasswordLength) characters" -ForegroundColor White
    Write-Host "    - Password Rotation Interval: $($age.PasswordAgeDays) days" -ForegroundColor White
} else {
    Write-Host "[!] VULNERABLE: Windows LAPS registry path does not exist. LAPS may not be configured." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on Local account management and password randomization
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.11 (LAPS Configuration)
* **Microsoft Security Guidance**: Windows Local Administrator Password Solution (LAPS) Technical Overview
