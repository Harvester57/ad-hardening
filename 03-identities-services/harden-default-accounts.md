# Hardening Requirement: Rename and Disable Default Administrator and Guest Accounts

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policies**:
    * `Accounts: Administrator account status`: `Disabled` (Note: Ensure LAPS or an alternative local admin exists first)
    * `Accounts: Guest account status`: `Disabled`
    * `Accounts: Rename administrator account`: `[CustomName]` (e.g., `SvcLocalAdmin`)
    * `Accounts: Rename guest account`: `[CustomName]` (e.g., `SvcLocalGuest`)
  * **Registry Location**:
    * Disable Admin: `HKLM\SAM\SAM\Domains\Account\Users\000001F4` (Managed via Local Security Policy / GPO)
    * Disable Guest: `HKLM\SAM\SAM\Domains\Account\Users\000001F5` (Managed via Local Security Policy / GPO)

---

## Rationale
Active Directory and local Windows environments initialize built-in accounts with fixed Relative Identifiers (RIDs). The default Administrator account always has RID 500, and the Guest account always has RID 501. 

Because these accounts are well-known, they are frequent targets for automated brute-force, password guessing, and identity enumeration attacks. In many environments, the built-in local administrator account has the same password across multiple systems, allowing attackers to move laterally if they crack one machine. Renaming these accounts increases the complexity of target identification, while disabling them prevents unauthorized logons entirely. If LAPS is active, it can rotate the password of the local administrator account even when the account is disabled, preserving safe recovery options.

---

## Legacy Impact & Compatibility
* **Script Dependencies**: Older scripts, setup packages, or orchestration tools that rely on the hardcoded username `Administrator` or `Guest` for authentication will fail. Update scripts to query by SID (e.g., `S-1-5-21-...-500`) or target the updated username.
* **Safe Mode Access**: If the local Administrator account is disabled and no other administrative account is functional, Safe Mode might limit recovery options. However, Windows automatically enables the built-in Administrator account in Safe Mode if no other local administrator accounts exist.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers` or `GPO_Hardening_MemberServers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following settings:
   * **Policy**: `Accounts: Administrator account status`
     * **Setting**: `Disabled`
   * **Policy**: `Accounts: Guest account status`
     * **Setting**: `Disabled`
   * **Policy**: `Accounts: Rename administrator account`
     * **Setting**: Enter a non-obvious custom name (e.g., `LocalMgmtAdmin`).
   * **Policy**: `Accounts: Rename guest account`
     * **Setting**: Enter a non-obvious custom name (e.g., `LocalMgmtGuest`).
5. Link the GPO to the appropriate Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to disable the local Administrator and Guest accounts locally using PowerShell.

```powershell
# Set-HardenDefaultAccounts.ps1
# Description: Disables the built-in local Administrator and Guest accounts locally.

Write-Host "Applying hardening requirement: Rename and Disable Default Accounts..." -ForegroundColor Cyan

# 1. Disable built-in local Administrator account
$adminAccount = Get-LocalUser -SID "S-1-5-32-544" | Where-Object { $_.SID -like "*-500" }
if ($adminAccount) {
    if ($adminAccount.Enabled) {
        Disable-LocalUser -Name $adminAccount.Name
        Write-Host "[+] Local Administrator account ($($adminAccount.Name)) disabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Administrator account ($($adminAccount.Name)) is already disabled." -ForegroundColor Yellow
    }
} else {
    Write-Warning "Built-in local Administrator account not found."
}

# 2. Disable built-in local Guest account
$guestAccount = Get-LocalUser -SID "S-1-5-32-544" | Where-Object { $_.SID -like "*-501" }
# Fallback to standard check if SID group matches local guest
if (-not $guestAccount) {
    $guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
}

if ($guestAccount) {
    if ($guestAccount.Enabled) {
        Disable-LocalUser -Name $guestAccount.Name
        Write-Host "[+] Local Guest account ($($guestAccount.Name)) disabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Guest account ($($guestAccount.Name)) is already disabled." -ForegroundColor Yellow
    }
} else {
    Write-Warning "Built-in local Guest account not found."
}
```

*To audit default accounts status locally:*
```powershell
# Get-DefaultAccountsStatus.ps1
# Description: Audits the enabled status of the built-in local Administrator and Guest accounts.

Write-Host "--- Auditing Default Accounts Status ---" -ForegroundColor Cyan

$adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }

if ($adminAccount) {
    $adminColor = if ($adminAccount.Enabled) { "Red" } else { "Green" }
    Write-Host "    - Local Administrator ($($adminAccount.Name)): Enabled = $($adminAccount.Enabled)" -ForegroundColor $adminColor
}

if ($guestAccount) {
    $guestColor = if ($guestAccount.Enabled) { "Red" } else { "Green" }
    Write-Host "    - Local Guest ($($guestAccount.Name)): Enabled = $($guestAccount.Enabled)" -ForegroundColor $guestColor
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on Default accounts and local user restriction
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.1.1 (Accounts: Administrator account status) and Section 2.3.1.2 (Accounts: Guest account status)
* **Microsoft Security Guidance**: Securing Built-in Administrator Accounts in Windows
