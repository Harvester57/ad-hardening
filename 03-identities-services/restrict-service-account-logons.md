# Hardening Requirement: Restrict Interactive Logons for Service Accounts

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Policies**:
    * `Deny log on locally`: Add Service Accounts security group (e.g., `Grp_ServiceAccounts`)
    * `Deny log on through Remote Desktop Services`: Add Service Accounts security group (e.g., `Grp_ServiceAccounts`)

---

## Rationale
Service accounts are frequent targets of brute-force and Kerberoasting attacks. If an adversary successfully cracks a service account's password offline, their immediate next step is to use those credentials to log on to domain systems to establish a footprint, dump credentials from memory, or perform administrative tasks.

By enforcing User Rights Assignment policies that explicitly deny service accounts the ability to log on locally (at the physical console) or through Remote Desktop Services (RDP), the threat of an interactive domain compromise via service credentials is neutralized. Even if a service account password is compromised, the attacker cannot utilize it to gain an interactive command shell or graphical desktop session on network endpoints or servers.

---

## Legacy Impact & Compatibility
* **Scheduled Tasks**: If service accounts are configured to run local scheduled tasks, they might require "Log on as a batch job" permissions. Make sure not to block "Log on as a batch job" if the service account has legitimate batch requirements.
* **Testing Phase**: Prior to implementing these deny policies in production GPOs, identify all service accounts, group them into a central security group, and verify that none of these accounts are used by administrators to log on to servers manually for management purposes.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the GPO linked to all domain systems (e.g., `GPO_Hardening_DomainMembers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Configure the following settings:
   * **Policy**: `Deny log on locally`
     * **Setting**: Define this policy and click **Add User or Group**. Add the dedicated security group containing all service accounts (e.g., `domain\Grp_ServiceAccounts` or `domain\Domain Users` if restricting specific sub-groups).
   * **Policy**: `Deny log on through Remote Desktop Services`
     * **Setting**: Define this policy and click **Add User or Group**. Add the dedicated security group containing all service accounts.
5. Click **Apply** and then **OK**.
6. Force a policy update on target servers (`gpupdate /force`).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Since User Rights Assignment is typically controlled by GPO or local security policy database (`secedit.sdb`), local changes can be made using the `secedit` command-line utility.

[Download Script: Set-DenyServiceLogons.ps1](implementation_scripts/Set-DenyServiceLogons.ps1)

```powershell
# Set-DenyServiceLogons.ps1
# Description: Configures local security database to deny interactive logons for a service account group.

Write-Host "Applying hardening requirement: Restrict Interactive Logons for Service Accounts..." -ForegroundColor Cyan

$SecDb = "$($env:temp)\localpolicy.sdb"
$SecCfg = "$($env:temp)\localpolicy.inf"
$GroupName = "Grp_ServiceAccounts" # Replace with the target security group name

# Export current security policy
secedit /export /cfg $SecCfg /quiet

# Read configuration file
$cfgContent = Get-Content -Path $SecCfg

# Define logon rights lines
$DenyLocalLine = "SeDenyInteractiveLogonRight = $GroupName"
$DenyRdpLine = "SeDenyRemoteInteractiveLogonRight = $GroupName"

# Check and update policy lines
$hasDenyLocal = $false
$hasDenyRdp = $false

$newCfg = New-Object System.Collections.Generic.List[string]

foreach ($line in $cfgContent) {
    if ($line -like "SeDenyInteractiveLogonRight*") {
        if ($line -notlike "*$GroupName*") {
            $line = "$($line), $GroupName"
        }
        $hasDenyLocal = $true
    }
    if ($line -like "SeDenyRemoteInteractiveLogonRight*") {
        if ($line -notlike "*$GroupName*") {
            $line = "$($line), $GroupName"
        }
        $hasDenyRdp = $true
    }
    $newCfg.Add($line) | Out-Null
}

if (-not $hasDenyLocal) {
    # Add to [Privilege Rights] section
    $privIndex = $newCfg.IndexOf("[Privilege Rights]")
    if ($privIndex -ge 0) {
        $newCfg.Insert($privIndex + 1, $DenyLocalLine)
    }
}

if (-not $hasDenyRdp) {
    $privIndex = $newCfg.IndexOf("[Privilege Rights]")
    if ($privIndex -ge 0) {
        $newCfg.Insert($privIndex + 1, $DenyRdpLine)
    }
}

# Save updated configuration
$newCfg | Set-Content -Path $SecCfg

# Configure local security policy
secedit /configure /db $SecDb /cfg $SecCfg /areas USER_RIGHTS /quiet

# Cleanup temporary files
Remove-Item -Path $SecCfg -Force
Remove-Item -Path $SecDb -Force

Write-Host "Local security policy updated: Deny log on locally/RDP applied to group $GroupName." -ForegroundColor Green
```

*To audit local User Rights Assignment settings:*
[Download Script: Get-DenyServiceLogonsStatus.ps1](audit_scripts/Get-DenyServiceLogonsStatus.ps1)

```powershell
# Get-DenyServiceLogonsStatus.ps1
# Description: Audits the Deny logon rights configurations locally.

Write-Host "--- Auditing Deny Logon Rights ---" -ForegroundColor Cyan

$SecCfg = "$($env:temp)\auditpolicy.inf"
secedit /export /cfg $SecCfg /quiet

$cfgContent = Get-Content -Path $SecCfg
$denyLocal = $cfgContent | Where-Object { $_ -like "SeDenyInteractiveLogonRight*" }
$denyRdp = $cfgContent | Where-Object { $_ -like "SeDenyRemoteInteractiveLogonRight*" }

Write-Host "[+] Local Deny Logon Rights settings:" -ForegroundColor Green
if ($denyLocal) {
    Write-Host "    - $denyLocal" -ForegroundColor White
} else {
    Write-Host "    - SeDenyInteractiveLogonRight is not configured." -ForegroundColor Yellow
}

if ($denyRdp) {
    Write-Host "    - $denyRdp" -ForegroundColor White
} else {
    Write-Host "    - SeDenyRemoteInteractiveLogonRight is not configured." -ForegroundColor Yellow
}

Remove-Item -Path $SecCfg -Force
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation on limiting administrative and service account interactive logons
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.2.14 (Deny log on locally) and Section 2.2.16 (Deny log on through Remote Desktop Services)
* **Microsoft Security Guidance**: User Rights Assignment Policies and Service Account Security
