# [REQ-OPS-012] Implement Automated Inactive Computer and User Account Cleanup

## Target Scope
* **Applicable Systems**: Active Directory User and Computer Accounts (Tiers 0, 1, and 2).
* **Operating Systems**: Active Directory Domain Services (All supported functional levels).

---

## Implementation Details
* **Priority**: Medium (Operational mitigation against lateral movement and backdoor persistence).
* **GPO Path / Registry Location**: N/A (Implemented via an automated PowerShell maintenance script scheduled to run periodically on a management host).

---

## Rationale
Inactive computer and user accounts remain in the directory due to gaps in the employee offboarding or machine decommissioning processes. 

These stale accounts represent a significant security risk:
1. **Backdoor Persistence**: Attackers targeting a domain can take control of inactive accounts (especially stale administrative accounts or service accounts with never-expiring passwords) to establish persistent, quiet access that is rarely monitored.
2. **Resource-Based Delegation Exploits**: Stale computer accounts can be targeted by attackers to construct resource-based constrained delegation (RBCD) attacks, allowing them to impersonate high-privilege services and eventually compromise the domain.
3. **Password Aging bypass**: Standard computers automatically change their passwords every 30 days. If a machine is powered off or disconnected, its password age increases. If computer passwords are not rotated, or if a stale computer account remains enabled, it increases the risk of offline password dumping and hash-relay.

Automatically disabling and isolating user accounts after 180 days of inactivity, and computer accounts after 90 days of inactivity, minimizes the active attack surface of the directory.

---

## Legacy Impact & Compatibility
* **Temporary Absence**: Employees on long-term leave (e.g., parental or medical leave) may have their accounts disabled automatically. Standard procedures must exist for the service desk to quickly re-enable accounts upon validation.
* **Lab and Staging Systems**: Test or staging servers that are powered down for long periods might have their computer accounts disabled. These accounts should be placed in excluded Organizational Units (OUs) or excluded via the script parameters.

---

## Implementation Steps

### Option A: Scheduled Maintenance Task Setup

1. Place the decommissioning script (`Decommission-InactiveAccounts.ps1`) in a secure administrative directory on a domain management host (e.g., `C:\ADMaintenance\Scripts\`).
2. Open **Task Scheduler** (`taskschd.msc`) on the management host.
3. Create a new task with the following properties:
   * **Account**: Run as a dedicated service account or `NT AUTHORITY\SYSTEM` (with delegated rights to modify user and computer accounts in target OUs).
   * **Trigger**: Weekly (e.g., every Sunday at 02:00 AM).
   * **Action**: Start a program:
     * **Program/script**: `powershell.exe`
     * **Arguments**: `-NoProfile -ExecutionPolicy Bypass -File "C:\ADMaintenance\Scripts\Decommission-InactiveAccounts.ps1" -LogPath "C:\ADMaintenance\Logs\"`
4. Enable logging and monitor execution logs to verify that accounts are correctly identified, disabled, and moved to the Stale OU.

---

### Option B: PowerShell & Active Directory Configuration (Remediation / Non-GPO)

To automate the identification, disabling, and isolation of inactive accounts:

[Download Script: Decommission-InactiveAccounts.ps1](implementation_scripts/Decommission-InactiveAccounts.ps1)

```powershell
# Decommission-InactiveAccounts.ps1
# Description: Disables and moves inactive user (180 days) and computer (90 days) accounts to a stale OU.

Import-Module ActiveDirectory

# Define thresholds
$UserInactivityDays = 180
$ComputerInactivityDays = 90

$UserCutoffDate = (Get-Date).AddDays(-$UserInactivityDays)
$ComputerCutoffDate = (Get-Date).AddDays(-$ComputerInactivityDays)

# Target OU for stale objects (adjust to your environment)
$StaleOU = "OU=StaleObjects,DC=domain,DC=local"
$Exclusions = @("Domain Controllers") # Exclude OUs containing DCs

if (-not (Get-ADOrganizationalUnit -Identity $StaleOU -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Stale OU '$StaleOU' does not exist. Creating it." -ForegroundColor Yellow
    New-ADOrganizationalUnit -Name "StaleObjects" -Path (Get-ADDomain).DistinguishedName -Verbose
}

Write-Host "Scanning for inactive user accounts (no logon in last $UserInactivityDays days)..." -ForegroundColor Cyan
$StaleUsers = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $UserCutoffDate -and Name -ne "Administrator" -and Name -ne "Guest"} -Properties LastLogonDate

foreach ($user in $StaleUsers) {
    # Verify the user is not in excluded paths
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($user.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "Disabling and moving inactive user: $($user.SamAccountName) (Last Logon: $($user.LastLogonDate))" -ForegroundColor Yellow
    Set-ADUser -Identity $user -Enabled $false -Description "Disabled by AD Decommissioning Script - Inactive for $UserInactivityDays days"
    Move-ADObject -Identity $user -TargetPath $StaleOU
}

Write-Host "`nScanning for inactive computer accounts (no logon in last $ComputerInactivityDays days)..." -ForegroundColor Cyan
$StaleComputers = Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -lt $ComputerCutoffDate} -Properties LastLogonDate

foreach ($comp in $StaleComputers) {
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($comp.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "Disabling and moving inactive computer: $($comp.Name) (Last Logon: $($comp.LastLogonDate))" -ForegroundColor Yellow
    Set-ADComputer -Identity $comp -Enabled $false -Description "Disabled by AD Decommissioning Script - Inactive for $ComputerInactivityDays days"
    Move-ADObject -Identity $comp -TargetPath $StaleOU
}

Write-Host "`nDecommissioning process completed." -ForegroundColor Green
```

*To audit the domain for stale user/computer accounts:*

[Download Script: Get-InactiveAccountsStatus.ps1](audit_scripts/Get-InactiveAccountsStatus.ps1)

```powershell
# Get-InactiveAccountsStatus.ps1
# Audits the directory for enabled but inactive user (180 days) and computer (90 days) accounts.

Import-Module ActiveDirectory

$UserInactivityDays = 180
$ComputerInactivityDays = 90

$UserCutoffDate = (Get-Date).AddDays(-$UserInactivityDays)
$ComputerCutoffDate = (Get-Date).AddDays(-$ComputerInactivityDays)

$StaleUsers = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $UserCutoffDate -and Name -ne "Administrator" -and Name -ne "Guest"} -Properties LastLogonDate
$StaleComputers = Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -lt $ComputerCutoffDate} -Properties LastLogonDate

$Exclusions = @("Domain Controllers")

$nonCompliantCount = 0

foreach ($user in $StaleUsers) {
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($user.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "[!] NON-COMPLIANT: User account '$($user.SamAccountName)' is enabled but inactive since $($user.LastLogonDate)" -ForegroundColor Red
    $nonCompliantCount++
}

foreach ($comp in $StaleComputers) {
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($comp.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "[!] NON-COMPLIANT: Computer account '$($comp.Name)' is enabled but inactive since $($comp.LastLogonDate)" -ForegroundColor Red
    $nonCompliantCount++
}

if ($nonCompliantCount -eq 0) {
    Write-Host "[+] COMPLIANT: No stale enabled user or computer accounts detected." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] NON-COMPLIANT: Detected $nonCompliantCount stale enabled accounts that need to be decommissioned." -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R45 (Auditing and disabling stale user/computer accounts)
* **CIS Benchmark**: Section 5.1 (User Account Control and password expirations)
* **PingCastle Rules**:
  * `S-C-Inactive` (Inactive computer check)
  * `P-Inactive` (Check for inactive administrator accounts)
  * `S-Inactive` (Inactive account check)
  * `S-PwdLastSet-90` (Check if all computers have changed their passwords in the last 3 months)
