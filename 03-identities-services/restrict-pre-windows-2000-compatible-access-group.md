# [REQ-ID-018] Restrict Pre-Windows 2000 Compatible Access Group

## Target Scope
* **Applicable Systems**: Domain Controllers, Domain Environment
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Restricted Groups GPO**: `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups` -> Group: `Pre-Windows 2000 Compatible Access` (SID: `S-1-5-32-554`)
  * **GPO Security Options**:
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options` -> `Network access: Let Everyone permissions apply to anonymous users` (Registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous` = `0`)
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options` -> `Network access: Do not allow anonymous enumeration of SAM accounts and shares` (Registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous` = `1`)
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options` -> `Network access: Do not allow anonymous enumeration of SAM accounts` (Registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM` = `1`)

---

## Rationale
The "Pre-Windows 2000 Compatible Access" group (SID: `S-1-5-32-554`) is a legacy Active Directory security group designed to provide backward compatibility for NT4-era operating systems. By default, this group has broad read permissions to all user and group object attributes within the domain.

Historically, groups like "Everyone" (`S-1-1-0`), "Anonymous Logon" (`S-1-5-7`), or "Authenticated Users" (`S-1-5-11`) were added to this group to maintain compatibility. The security risks include:

1. **Information Enumeration**: Any authenticated user (or an unauthenticated attacker via anonymous/everyone permissions) can query the Active Directory database to enumerate user lists, group memberships, trust details, and account metadata.
2. **Reconnaissance Surface**: Attackers use null-sessions or low-privileged domain accounts to profile the entire AD infrastructure, mapping target groups (like Domain Admins) and identifying service accounts for targeted attacks like Kerberoasting.
3. **Implicit Trust Abuse**: Relying on legacy broad-read access bypasses modern Active Directory object-level Access Control List (ACL) restrictions.

Removing insecure principals from this group and enforcing anonymous access restrictions restricts AD object access to authenticated, authorized accounts only.

---

## Legacy Impact & Compatibility
* **Legacy Integrations**: Non-Windows devices or legacy operating systems (such as older Linux integrations utilizing SSSD or Samba, Cisco ISE, or third-party reporting tools) may rely on the broad permissions of this group to query domain objects. Removing "Authenticated Users" can cause these services to fail to authenticate users or map group memberships.
* **Active Directory Certificate Services (AD CS)**: Integrated Enterprise CAs are added to this group by default to enable certificate management policies. If the restricted certificate manager feature is not in use, these CA servers can be safely removed; otherwise, removing them can impact enrollment processes.
* **Mitigations**:
  * Prior to removing "Authenticated Users", verify whether any applications fail to query AD attributes.
  * If a specific service or application fails, do not re-add broad groups to the Pre-Windows 2000 group. Instead, grant the specific application service account or computer account the necessary explicit "Read" permissions on target Organizational Units (OUs).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Restrict Group Membership
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Create or edit a GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups`
4. Right-click **Restricted Groups** and select **Add Group...**.
5. Type **Pre-Windows 2000 Compatible Access** and click **OK**.
6. In the group properties dialog, under **Members of this group**, ensure the list is empty (or contains only authorized service accounts/CA computer accounts). Ensure **Everyone**, **Anonymous Logon**, and **Authenticated Users** are not listed.
7. Click **Apply** and then **OK**.

#### Step 2: Configure Supporting Anonymous Access Policies
1. In the same GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Configure the following policies:
   * **Policy**: `Network access: Let Everyone permissions apply to anonymous users`
     * **Setting**: `Disabled`
   * **Policy**: `Network access: Do not allow anonymous enumeration of SAM accounts and shares`
     * **Setting**: `Enabled`
   * **Policy**: `Network access: Do not allow anonymous enumeration of SAM accounts`
     * **Setting**: `Enabled`
3. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and remediate these configurations.

#### 1. Local Audit (Audit-PreWin2000Group.ps1)

[Download Script: Audit-PreWin2000Group.ps1](audit_scripts/Audit-PreWin2000Group.ps1)

```powershell
# Audit-PreWin2000Group.ps1
# Description: Audits the Pre-Windows 2000 Compatible Access group membership and local LSA registry configurations.

Import-Module ActiveDirectory

Write-Host "--- Auditing Pre-Windows 2000 Compatible Access Settings ---" -ForegroundColor Cyan

$GroupSid = "S-1-5-32-554"
$CriticalNonCompliantSids = @("S-1-1-0", "S-1-5-7") # Everyone, Anonymous Logon
$RestrictedNonCompliantSids = @("S-1-5-11")          # Authenticated Users (default in modern systems, high legacy impact if removed)
$Vulnerable = $false
$HasWarning = $false

# 1. Audit Group Membership
try {
    $Group = Get-ADGroup -Identity $GroupSid -Properties Members -ErrorAction Stop
    $MembersSids = New-Object System.Collections.Generic.List[string]

    foreach ($MemberDN in $Group.Members) {
        $MemberObj = Get-ADObject -Identity $MemberDN -ErrorAction SilentlyContinue
        if ($null -ne $MemberObj) {
            $MembersSids.Add($MemberObj.SID.Value) | Out-Null
        }
    }

    # Check for Critical SIDs (Everyone, Anonymous Logon)
    foreach ($Sid in $CriticalNonCompliantSids) {
        if ($MembersSids.Contains($Sid)) {
            $Vulnerable = $true
            $Name = ""
            if ($Sid -eq "S-1-1-0") { $Name = "Everyone" }
            elseif ($Sid -eq "S-1-5-7") { $Name = "Anonymous Logon" }

            Write-Host "VULNERABLE: '$($Name)' ($($Sid)) is a member of the Pre-Windows 2000 Compatible Access group." -ForegroundColor Red
        }
    }

    # Check for Authenticated Users (High legacy impact warning)
    foreach ($Sid in $RestrictedNonCompliantSids) {
        if ($MembersSids.Contains($Sid)) {
            $HasWarning = $true
            Write-Host "WARNING: 'Authenticated Users' ($($Sid)) is a member of the Pre-Windows 2000 Compatible Access group. (This is default in modern systems; remove with caution)." -ForegroundColor Yellow
        }
    }

    if (-not $Vulnerable -and -not $HasWarning) {
        Write-Host "Status: Compliant. Pre-Windows 2000 Compatible Access group membership is restricted." -ForegroundColor Green
    } elseif (-not $Vulnerable) {
        Write-Host "Status: Compliant (with warnings). Critical groups are removed, but legacy/default Authenticated Users remains." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not query Pre-Windows 2000 Compatible Access group membership. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Audit LSA Registry Security Settings
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$Settings = @{
    "EveryoneIncludesAnonymous" = 0
    "RestrictAnonymous"         = 1
    "RestrictAnonymousSAM"      = 1
}

foreach ($Key in $Settings.Keys) {
    try {
        if (Test-Path $LsaPath) {
            $Value = Get-ItemPropertyValue -Path $LsaPath -Name $Key -ErrorAction Stop
            $TargetValue = $Settings[$Key]
            
            if ($Value -ne $TargetValue) {
                Write-Host "VULNERABLE: LSA Registry Key '$($Key)' is set to $($Value) (should be $($TargetValue))." -ForegroundColor Red
            } else {
                Write-Host "Status: Compliant. LSA Registry Key '$($Key)' is set to $($TargetValue)." -ForegroundColor Green
            }
        } else {
            Write-Host "VULNERABLE: LSA registry path does not exist." -ForegroundColor Red
        }
    } catch {
        Write-Host "VULNERABLE: Could not audit LSA key '$($Key)'. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

#### 2. Local Remediation (Set-PreWin2000Group.ps1)

[Download Script: Set-PreWin2000Group.ps1](implementation_scripts/Set-PreWin2000Group.ps1)

```powershell
# Set-PreWin2000Group.ps1
# Description: Restricts Pre-Windows 2000 Compatible Access group membership and configures LSA registry security keys.

Import-Module ActiveDirectory

# Configuration Switch: Set to $true if you want to remove 'Authenticated Users' (S-1-5-11).
# WARNING: Removing Authenticated Users can break legacy Samba/SSSD clients, Cisco ISE, and other querying integrations.
$RemoveAuthenticatedUsers = $false

Write-Host "Applying hardening requirement: Restrict Pre-Windows 2000 Compatible Access..." -ForegroundColor Cyan

$GroupSid = "S-1-5-32-554"
$NonCompliantSids = @("S-1-1-0", "S-1-5-7") # Critical SIDs to remove (Everyone, Anonymous Logon)

if ($RemoveAuthenticatedUsers) {
    $NonCompliantSids += "S-1-5-11" # Add Authenticated Users to the removal list
}

# 1. Remediate Group Membership
try {
    $Group = Get-ADGroup -Identity $GroupSid -Properties Members -ErrorAction Stop
    $MembersToRemove = New-Object System.Collections.Generic.List[string]

    foreach ($MemberDN in $Group.Members) {
        $MemberObj = Get-ADObject -Identity $MemberDN -ErrorAction SilentlyContinue
        if ($null -ne $MemberObj) {
            $Sid = $MemberObj.SID.Value
            if ($NonCompliantSids -contains $Sid) {
                $MembersToRemove.Add($MemberDN) | Out-Null
            }
        }
    }

    if ($MembersToRemove.Count -gt 0) {
        foreach ($MemberDN in $MembersToRemove) {
            try {
                Remove-ADGroupMember -Identity $GroupSid -Members $MemberDN -Confirm:$false -ErrorAction Stop
                Write-Host "[+] Successfully removed '$($MemberDN)' from the group." -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to remove '$($MemberDN)'. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[-] No non-compliant members found in Pre-Windows 2000 Compatible Access group." -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to remediate Pre-Windows 2000 Compatible Access group membership. Error: $($_.Exception.Message)"
}

# 2. Remediate LSA Registry Settings
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$Settings = @{
    "EveryoneIncludesAnonymous" = 0
    "RestrictAnonymous"         = 1
    "RestrictAnonymousSAM"      = 1
}

foreach ($Key in $Settings.Keys) {
    try {
        if (-not (Test-Path $LsaPath)) {
            New-Item -Path $LsaPath -Force | Out-Null
        }
        
        $TargetValue = $Settings[$Key]
        Set-ItemProperty -Path $LsaPath -Name $Key -Value $TargetValue -Type DWord -ErrorAction Stop
        Write-Host "[+] Registry Key '$($Key)' successfully set to $($TargetValue)." -ForegroundColor Green
    } catch {
        Write-Error "Failed to apply LSA Registry Key '$($Key)'. Error: $($_.Exception.Message)"
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 3.1.2 (Management of default groups and security options)
* **CIS Benchmark**:
  * CIS Windows Server 2016 Benchmark v2.0.0 - Section 2.3.10.2 (Network access: Do not allow anonymous enumeration of SAM accounts)
  * CIS Windows Server 2016 Benchmark v2.0.0 - Section 2.3.10.5 (Network access: Let Everyone permissions apply to anonymous users)
  * CIS Windows Server 2016 Benchmark v2.0.0 - Section 2.3.10.10 (Network access: Restrict anonymous access to Named Pipes and Shares)
* **Microsoft Security Guidance**: Active Directory Pre-Windows 2000 Compatible Access security recommendations
