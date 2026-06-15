# [REQ-ID-002] Enable Local Administrator Password Solution (LAPS)

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients, Domain Controllers
* **Operating Systems**: 
  * **Modern Windows LAPS**: Windows Server 2019/2022/2025 (with April 11, 2023 cumulative update or later), Windows 10/11 (with April 11, 2023 cumulative update or later)
  * **Legacy Microsoft LAPS**: Windows Server 2016 (and older), Windows 7/8/8.1, Windows Server 2008 R2/2012/2012 R2

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\System\LAPS`
  * **Registry Location (GPO Policies)**: `HKLM\Software\Policies\Microsoft\Windows\LAPS`
  * **Registry Location (Local / CSP Settings)**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`

---

## Rationale
In standard Active Directory setups, local administrator accounts on member servers and client workstations often share the same password. If a single machine is compromised and the local administrator password hash is extracted (e.g., from LSASS memory or SAM database), attackers can leverage Pass-the-Hash (PtH) techniques to log on to other domain machines laterally.

Implementing the Local Administrator Password Solution (LAPS) completely mitigates this lateral movement vector by automatically generating a unique, complex password for the specified local administrator account on each machine. These passwords are changed periodically and stored securely in a confidential attribute (`msLAPS-Password` or `ms-Mcs-AdmPwd`) on the computer's Active Directory object. Read access is restricted to authorized administrative groups.

### Modern Windows LAPS vs. Legacy Microsoft LAPS
Microsoft introduced modern **Windows LAPS** as a native OS feature in April 2023, deprecating the older, installer-based **Legacy Microsoft LAPS** (MSI package). Key benefits of modern Windows LAPS include:
1. **Password Encryption**: Cryptographically protects passwords stored in Active Directory, preventing exposure to unauthorized users who might inspect directory attributes.
2. **Directory Services Restore Mode (DSRM) Backup**: Supports backing up DSRM account passwords on Domain Controllers (running Windows Server 2019 and newer).
3. **Password History**: Allows retrieval of previous passwords to support system restores.
4. **Post-Authentication Actions**: Forces an automated password reset and logs off the managed administrator account after interactive use, restricting the lifetime of exposed credentials on a device.
5. **Azure AD / Microsoft Entra ID Support**: Natively supports backing up passwords directly to the cloud for cloud-joined or hybrid-joined devices.

---

## Legacy Impact & Compatibility
* **LAPS Client Dependency**: Devices must have the Windows LAPS extension installed (native to modern Windows updates) or have the Classic LAPS client installed.
* **Schema Extension**: The Active Directory schema must be extended to include LAPS attributes before clients can write passwords.
* **AD Permissions**: Ensure permissions on computer objects are configured to block non-administrator users from reading the confidential password attributes.
* **Encryption Prerequisite**: Encryption of LAPS passwords requires a Domain Functional Level of at least Windows Server 2016. If the functional level is lower, passwords must be stored in clear text.
* **DSRM Prerequisite**: DSRM password backup is only supported on Domain Controllers running Windows Server 2019 or later.
* **Windows Server 2016 Warning**: Windows Server 2016 domain controllers and member servers do not support modern Windows LAPS natively. For Windows Server 2016 systems, the **Legacy Microsoft LAPS** client (MSI-based) must be deployed and maintained.

---

## Prerequisites & Active Directory Preparation

Before configuring Windows LAPS client policies, the Active Directory forest must be prepared to support modern LAPS attributes and access controls.

### Step 1: Update Active Directory Schema
Extend the Active Directory schema to add the modern Windows LAPS attributes. This must be run by an administrator with Schema Admins privileges in the forest root domain. Run this on a Domain Controller running Windows Server 2019 or later, or any system with the LAPS PowerShell module installed:
```powershell
Import-Module Laps
Update-LapsADSchema -Verbose
```

### Step 2: Configure Organizational Unit Permissions
Computers must be authorized to write their own local administrator passwords to their corresponding computer object in Active Directory. Grant this permission by running the following command against the Organizational Units (OUs) that contain the target computers:
```powershell
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=domain,DC=local" -Verbose
```

### Step 3: Grant Password Query Permissions
By default, only Domain Admins have permissions to read LAPS passwords. Grant password query permissions to dedicated administrative groups (e.g., tier-2 support technicians):
```powershell
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=domain,DC=local" -AllowedPrincipals @("DOMAIN\Tier2-Support") -Verbose
```

### Step 4: Grant Password Reset (Expiration) Permissions
Grant permissions to authorize administrative groups to force an early password rotation (by marking the password as expired in AD):
```powershell
Set-LapsADResetPasswordPermission -Identity "OU=Workstations,DC=domain,DC=local" -AllowedPrincipals @("DOMAIN\Tier2-Support") -Verbose
```

### Step 5: Audit Extended Rights
Audit and verify that no unauthorized groups or users possess extended rights on the OU which would allow them to bypass confidentiality settings and read password attributes:
```powershell
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=domain,DC=local"
```

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
   * **Policy**: `Do not allow password expiration time longer than required by policy`
     * **Setting**: `Enabled`
   * **Policy**: `Enable password encryption`
     * **Setting**: `Enabled`
   * **Policy**: `Password Settings`
     * **Setting**: `Enabled`
     * **Options**: Set complexity to `Large letters + small letters + numbers + special characters`, length to `20`, and age to `30` days.
   * **Policy**: `Post-authentication actions`
     * **Setting**: `Enabled`
     * **Options**: Set Grace period (hours) to `8`, Actions to `Reset the password and logoff the managed account`.
   * **Policy**: `Enable local admin password management`
     * **Setting**: `Enabled`
5. Link the GPO to the Organizational Units (OUs) containing member servers and client workstations.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing or standalone systems) or if the control is not manageable via standard GPO GUI interfaces.

[Download Script: Configure-LAPS.ps1](implementation_scripts/Configure-LAPS.ps1)

```powershell
# Configure-LAPS.ps1
# Description: Configures Windows LAPS parameters in the registry.

Write-Host "Applying hardening requirement: Enable Local Administrator Password Solution..." -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enable LAPS management
Set-ItemProperty -Path $RegPath -Name "EnableLAPS" -Value 1 -Type DWord
# 2 = Backup to Active Directory
Set-ItemProperty -Path $RegPath -Name "BackupDirectory" -Value 2 -Type DWord
# 1 = Do not allow password expiration time longer than required by policy
Set-ItemProperty -Path $RegPath -Name "PasswordExpirationProtectionEnabled" -Value 1 -Type DWord
# 1 = Enable password encryption
Set-ItemProperty -Path $RegPath -Name "ADPasswordEncryptionEnabled" -Value 1 -Type DWord
# 4 = Letters + numbers + special characters
Set-ItemProperty -Path $RegPath -Name "PasswordComplexity" -Value 4 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordLength" -Value 20 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -Value 30 -Type DWord
# 8 = Grace period of 8 hours
Set-ItemProperty -Path $RegPath -Name "PostAuthenticationResetDelay" -Value 8 -Type DWord
# 3 = Reset the password and logoff the managed account
Set-ItemProperty -Path $RegPath -Name "PostAuthenticationActions" -Value 3 -Type DWord

Write-Host "Windows LAPS configuration registry settings applied successfully." -ForegroundColor Green
```

---

## Operation & Monitoring

### Force Policy Processing
Trigger Windows LAPS to immediately query GPO and process the current policy (e.g., generate a new password if expired):
```powershell
Invoke-LapsPolicyProcessing
```

### Retrieve Password from Active Directory
Query and retrieve the managed administrator password in plain text:
```powershell
Get-LapsADPassword -Identity "COMPUTER-NAME" -AsPlainText
```

### Force Early Password Rotation
Set the scheduled password expiration to the current time, forcing the computer to rotate the password during its next processing cycle:
```powershell
Set-LapsADPasswordExpirationTime -Identity "COMPUTER-NAME"
```
Or force immediate local rotation directly on the managed client system:
```powershell
Reset-LapsPassword
```

### Diagnostics & Event Logs
Audit Windows LAPS actions in the Windows Event Viewer:
* **Log Channel Path**: `Applications and Services Logs \ Microsoft \ Windows \ LAPS \ Operational`
* **Key Event IDs**:
  * `10018`: LAPS password successfully backed up to Active Directory.
  * `10019`: LAPS password backup to Active Directory failed.
  * `10020`: LAPS password encryption failed.

---

## Audit verification

Use the following script to verify the setting has been applied:

[Download Script: Get-LAPSStatus.ps1](audit_scripts/Get-LAPSStatus.ps1)

```powershell
# Get-LAPSStatus.ps1
# Description: Checks the Windows LAPS registry parameters.

Write-Host "--- Auditing LAPS Registry Configuration ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

if (Test-Path $RegPath) {
    $enableLAPS = Get-ItemProperty -Path $RegPath -Name "EnableLAPS" -ErrorAction SilentlyContinue
    $backupDir = Get-ItemProperty -Path $RegPath -Name "BackupDirectory" -ErrorAction SilentlyContinue
    $expirationProtection = Get-ItemProperty -Path $RegPath -Name "PasswordExpirationProtectionEnabled" -ErrorAction SilentlyContinue
    $encryption = Get-ItemProperty -Path $RegPath -Name "ADPasswordEncryptionEnabled" -ErrorAction SilentlyContinue
    $complexity = Get-ItemProperty -Path $RegPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue
    $length = Get-ItemProperty -Path $RegPath -Name "PasswordLength" -ErrorAction SilentlyContinue
    $age = Get-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -ErrorAction SilentlyContinue
    $resetDelay = Get-ItemProperty -Path $RegPath -Name "PostAuthenticationResetDelay" -ErrorAction SilentlyContinue
    $actions = Get-ItemProperty -Path $RegPath -Name "PostAuthenticationActions" -ErrorAction SilentlyContinue
    
    Write-Host "[+] LAPS Configuration Found under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ForegroundColor Green
    
    # Audit EnableLAPS
    if ($null -ne $enableLAPS -and $enableLAPS.EnableLAPS -eq 1) {
        Write-Host "    - LAPS Management: Enabled" -ForegroundColor White
    } else {
        Write-Host "    - LAPS Management: NOT ENABLED (EnableLAPS = 0 or missing)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit BackupDirectory
    if ($null -ne $backupDir -and $backupDir.BackupDirectory -eq 2) {
        Write-Host "    - Backup Directory: $($backupDir.BackupDirectory) (2 = Active Directory)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $backupDir) { $val = $backupDir.BackupDirectory }
        Write-Host "    - Backup Directory: $($val) (Expected: 2 = Active Directory)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Expiration Protection
    if ($null -ne $expirationProtection -and $expirationProtection.PasswordExpirationProtectionEnabled -eq 1) {
        Write-Host "    - Expiration Protection: Enabled" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $expirationProtection) { $val = $expirationProtection.PasswordExpirationProtectionEnabled }
        Write-Host "    - Expiration Protection: $($val) (Expected: 1)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Encryption
    if ($null -ne $encryption -and $encryption.ADPasswordEncryptionEnabled -eq 1) {
        Write-Host "    - Password Encryption: Enabled" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $encryption) { $val = $encryption.ADPasswordEncryptionEnabled }
        Write-Host "    - Password Encryption: $($val) (Expected: 1)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Complexity
    if ($null -ne $complexity -and $complexity.PasswordComplexity -eq 4) {
        Write-Host "    - Password Complexity: $($complexity.PasswordComplexity) (4 = Large + small + numbers + special characters)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $complexity) { $val = $complexity.PasswordComplexity }
        Write-Host "    - Password Complexity: $($val) (Expected: 4)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Length
    if ($null -ne $length -and $length.PasswordLength -ge 15) {
        Write-Host "    - Password Length: $($length.PasswordLength) characters (Secure, >= 15)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $length) { $val = $length.PasswordLength }
        Write-Host "    - Password Length: $($val) (Expected: >= 15)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Age
    if ($null -ne $age -and $age.PasswordAgeDays -le 30) {
        Write-Host "    - Password Rotation Interval: $($age.PasswordAgeDays) days (Secure, <= 30)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $age) { $val = $age.PasswordAgeDays }
        Write-Host "    - Password Rotation Interval: $($val) (Expected: <= 30)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Post-Authentication Reset Delay
    if ($null -ne $resetDelay -and $resetDelay.PostAuthenticationResetDelay -le 8 -and $resetDelay.PostAuthenticationResetDelay -gt 0) {
        Write-Host "    - Post-Auth Reset Delay: $($resetDelay.PostAuthenticationResetDelay) hours (Secure, <= 8)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $resetDelay) { $val = $resetDelay.PostAuthenticationResetDelay }
        Write-Host "    - Post-Auth Reset Delay: $($val) (Expected: <= 8 and > 0)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Post-Authentication Actions
    if ($null -ne $actions -and $actions.PostAuthenticationActions -eq 3) {
        Write-Host "    - Post-Auth Actions: $($actions.PostAuthenticationActions) (3 = Reset and logoff)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $actions) { $val = $actions.PostAuthenticationActions }
        Write-Host "    - Post-Auth Actions: $($val) (Expected: 3 = Reset and logoff)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
} else {
    Write-Host "[!] VULNERABLE: Windows LAPS registry path does not exist. LAPS is not configured." -ForegroundColor Red
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
* **Microsoft Documentation**: [Windows LAPS Overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
* **Microsoft Documentation**: [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
* **ANSSI AD Hardening Guide**: Section on Local account management and password randomization
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.11 (LAPS Configuration)
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark - Section 18.9.25 (LAPS Configuration)
