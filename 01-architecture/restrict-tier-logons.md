# [REQ-ARCH-001] Restrict Tier Logons

## Target Scope
* **Applicable Systems**: Tier 1 member servers and Tier 2 client workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment

---

## Rationale
To successfully enforce the administrative tiering model, the boundaries must be programmatically restricted. Active Directory administrative groups (such as `Domain Admins`, `Enterprise Admins`, and `Schema Admins`) must be explicitly blocked from authenticating to lower-tier systems. 

If these permissions are not restricted, a Tier 0 administrator might use their account to troubleshoot a Tier 1 server or Tier 2 workstation. This action caches their administrative password hash or Kerberos Ticket Granting Ticket (TGT) in the local memory of the target machine. If that machine has been compromised, an attacker can extract those credentials and compromise the entire Active Directory domain.

By configuring Group Policy objects to explicitly deny logon rights (interactive, network, and Remote Desktop) for high-tier administrative accounts on lower-tier systems, you prevent accidental or unauthorized exposure of high-privilege credentials.

---

## Legacy Impact & Compatibility
* **Administration Access**: Technicians cannot log on to workstations or member servers using Domain Admin accounts. They must use dedicated administrative credentials assigned to that specific tier (e.g., `a2-florian` for workstation support) or use local administrator accounts managed by LAPS.
* **Remote Support Tools**: Automated support tools or scripts that authenticate using Domain Admin accounts to query local client registry hives or modify system files will be blocked. These tools must be reconfigured to authenticate using dedicated service accounts or Tier 1/2 administrative accounts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To prevent Tier 0 credentials from being exposed on Tier 1 and Tier 2 systems, configure the logon restrictions using GPOs linked to the Tier 1 (Member Servers) and Tier 2 (Workstations) OUs.

#### 1. Configure Tier 1 Logon Restrictions GPO
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create a GPO linked to the **Tier 1 Member Servers** OU (e.g., `GPO_Restrictions_Tier1`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Define and configure the following policies:
   * **Deny access to this computer from the network**: Add `Domain Admins`, `Enterprise Admins`, `Schema Admins`.
   * **Deny log on as a batch job**: Add `Domain Admins`, `Enterprise Admins`, `Schema Admins`.
   * **Deny log on as a service**: Add `Domain Admins`, `Enterprise Admins`, `Schema Admins`.
   * **Deny log on locally**: Add `Domain Admins`, `Enterprise Admins`, `Schema Admins`.
   * **Deny log on through Remote Desktop Services**: Add `Domain Admins`, `Enterprise Admins`, `Schema Admins`.

#### 2. Configure Tier 2 Logon Restrictions GPO
1. Create a GPO linked to the **Tier 2 Workstations** OU (e.g., `GPO_Restrictions_Tier2`).
2. Navigate to the same path:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
3. Configure the policies to deny access for **both** Tier 0 and Tier 1 administrative groups:
   * **Deny access to this computer from the network**: Add Tier 0 groups (`Domain Admins`, `Enterprise Admins`, `Schema Admins`) and Tier 1 administrative groups.
   * **Deny log on as a batch job**: Add Tier 0 and Tier 1 administrative groups.
   * **Deny log on as a service**: Add Tier 0 and Tier 1 administrative groups.
   * **Deny log on locally**: Add Tier 0 and Tier 1 administrative groups.
   * **Deny log on through Remote Desktop Services**: Add Tier 0 and Tier 1 administrative groups.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this script to configure local security database files via `secedit` to deny specified administrative groups from logging on locally, over the network, or via Remote Desktop.

[Download Script: Set-LocalLogonRestrictions.ps1](implementation_scripts/Set-LocalLogonRestrictions.ps1)

```powershell
# Set-LocalLogonRestrictions.ps1
# Configures secedit User Rights Assignment to block domain administrative groups.

# 1. Define groups to block (Tier 0 admin groups)
$DenyGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

# 2. Translate group names to SID strings
$SIDs = foreach ($group in $DenyGroups) {
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($group)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        "*$sid"
    } catch {
        Write-Warning "Could not resolve SID for group: $group. Skipping."
    }
}

if ($SIDs.Count -eq 0) {
    Write-Error "No valid group SIDs resolved. Exiting."
    exit 1
}

# 3. Define the temporary paths for secedit config
$tempDir = [System.IO.Path]::GetTempPath()
$secConfigPath = Join-Path $tempDir "sec_config.inf"
$secDbPath = Join-Path $tempDir "sec_db.sdb"

# 4. Export current local security policy
secedit /export /cfg $secConfigPath /areas USER_RIGHTS /quiet

# 5. Modify exported config to inject our deny rules
$configContent = Get-Content -Path $secConfigPath
$NewContent = [System.Collections.Generic.List[string]]::new()
$InUserRights = $false

$PolicyEntries = @(
    "SeDenyInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight"
)

foreach ($line in $configContent) {
    if ($line -match '^\[Privilege Rights\]') {
        $InUserRights = $true
        $NewContent.Add($line)
        continue
    }
    if ($InUserRights -and $line -match '^\[') {
        $InUserRights = $false
    }
    
    # Filter out existing lines for the policies we configure
    $matched = $false
    foreach ($entry in $PolicyEntries) {
        if ($line -match "^$entry\s*=") {
            $matched = $true
            break
        }
    }
    
    if (-not $matched) {
        $NewContent.Add($line)
    }
}

# Insert new rules into [Privilege Rights] section
$InsertIndex = $NewContent.FindIndex({ $args[0] -match '^\[Privilege Rights\]' })
if ($InsertIndex -ge 0) {
    $Offset = 1
    $FormattedSIDs = $SIDs -join ","
    foreach ($policy in $PolicyEntries) {
        $NewContent.Insert($InsertIndex + $Offset, "$policy = $FormattedSIDs")
        $Offset++
    }
}

# Save new configuration
$NewContent | Out-File -FilePath $secConfigPath -Encoding utf16

# 6. Apply configuration using secedit
Write-Host "Applying User Rights Assignment restrictions via secedit..." -ForegroundColor Cyan
$process = Start-Process secedit -ArgumentList "/configure /db $secDbPath /cfg $secConfigPath /areas USER_RIGHTS /quiet" -Wait -NoNewWindow -PassThru

# Cleanup temporary database files
if (Test-Path $secConfigPath) { Remove-Item $secConfigPath -Force }
if (Test-Path $secDbPath) { Remove-Item $secDbPath -Force }

if ($process.ExitCode -eq 0) {
    Write-Host "Logon restrictions applied successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to apply logon restrictions. Exit code: $($process.ExitCode)"
}
```

*To audit active logon restriction settings locally:*
[Download Script: Test-LocalLogonRestrictions.ps1](audit_scripts/Test-LocalLogonRestrictions.ps1)

```powershell
# Test-LocalLogonRestrictions.ps1
# Audits local security policies to check if SeDeny rights are populated.

Write-Host "--- Auditing Local User Rights Assignments ---" -ForegroundColor Cyan

$tempDir = [System.IO.Path]::GetTempPath()
$secConfigPath = Join-Path $tempDir "sec_audit.inf"

# Export current configuration
secedit /export /cfg $secConfigPath /areas USER_RIGHTS /quiet

$configContent = Get-Content -Path $secConfigPath
$PoliciesToTest = @(
    "SeDenyInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight"
)

foreach ($policy in $PoliciesToTest) {
    $match = $configContent | Where-Object { $_ -match "^$policy\s*=" }
    if ($match) {
        # Check if it contains domain admin or other groups
        Write-Host "    - Policy '$policy' is configured: $match" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: Policy '$policy' is not defined (No accounts denied)." -ForegroundColor Red
    }
}

if (Test-Path $secConfigPath) { Remove-Item $secConfigPath -Force }
```

---

## 🔗 Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations R1, R2, and R3 (Administrative isolation and account restriction rules)
* **CIS Microsoft Windows Server 2016 Benchmark**: Section 18.2 (User Rights Assignment)
