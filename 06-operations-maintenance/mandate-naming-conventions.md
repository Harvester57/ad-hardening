# [REQ-OPS-007] Mandate Naming Conventions for GPOs, OUs, and User Accounts

## Target Scope
* **Applicable Systems**: Active Directory Domain Services (Logical Structure), Management Stations, Domain Controllers
* **Operating Systems**: Windows Server 2016+, Windows 10 Enterprise, Windows 11 Enterprise

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Active Directory Directory Objects (Logical Policy)

---

## Rationale
Active Directory environments, particularly those with administrative tiering, require strict logical organization to maintain security boundaries and prevent operational errors. The lack of standard naming conventions leads to several security and operational risks:
1. **Administrative Confusions and Misconfigurations**: Without clear identifiers, administrators might link a highly restrictive Tier 0 GPO to a Tier 2 Client Workstations OU, causing system outages or security bypasses.
2. **Audit and Monitoring Gaps**: Security monitoring tools and SIEM parsers rely on predictable account and resource patterns (such as `a0-` for Tier 0 admin actions) to flag abnormal logons or lateral movement attempts.
3. **Privilege Escalation**: Predictable naming conventions for standard accounts, combined with clear tier prefixes for administrative accounts, prevent users from mistakenly allocating administrative permissions to non-admin accounts.
4. **Configuration Drift**: Group Policy Objects without descriptions or identifiers become "orphaned" or modified by different teams without clear change tracking, leading to undocumented changes that weaken the security posture.

Enforcing structured GPO, OU, and Account naming conventions, combined with a mandatory description template for GPOs, establishes self-documenting metadata that can be programmatically audited to ensure long-term directory integrity.

---

## Legacy Impact & Compatibility
Applying naming conventions is a logical and administrative change, meaning it does not break underlying cryptographic protocols or network services. However:
1. **Renaming Existing Objects**: Renaming existing user accounts, OUs, or GPOs can break existing automation scripts, application binds (LDAP queries using hardcoded DN paths), and GPO links if not updated simultaneously.
2. **Phased Migration**: Rather than renaming existing legacy structures abruptly, organizations must adopt a phased approach:
   * Enforce conventions on all new GPOs, OUs, and accounts.
   * Run automated audit scripts to inventory non-compliant objects.
   * Coordinate scheduled maintenance windows to update and rename legacy objects.

---

## Implementation Steps

### Option A: Manual Logical Configuration (GUI)

#### 1. Organizational Unit (OU) Hierarchy Design
Establish a clear, tiered OU hierarchy in **Active Directory Users and Computers** (`dsa.msc`).
All custom OUs must follow the format:
`<Tier>-<ObjectType>-<Function>`
* **Tier**: `T0` (Tier 0), `T1` (Tier 1), `T2` (Tier 2), or `Global` (common infrastructure/domain-wide settings).
* **ObjectType**: `Computers`, `Users`, `Groups`, or `ServiceAccounts`.
* **Function**: Descriptive PascalCase text indicating the target scope.

Examples of compliant OUs:
* `T0-Computers-DomainControllers` (for DCs)
* `T1-Computers-ApplicationServers` (for Tier 1 member servers)
* `T2-Computers-Workstations` (for Tier 2 client computers)
* `T0-Users-Admins` (for Tier 0 administrative users)
* `T1-Users-ServiceAccounts` (for Tier 1 application/service accounts)

#### 2. Group Policy Object (GPO) Naming Scheme
Create GPOs in the **Group Policy Management Console** (`gpmc.msc`) using the following naming structure:
`GPO_<Scope>_<Class>_<Name>`
* **Scope**: `T0` (Tier 0), `T1` (Tier 1), `T2` (Tier 2), or `Global` (domain-wide).
* **Class**: `Hardening` (security settings), `Config` (operational settings), `Restricted` (restricted logons/groups), or `Software` (installations).
* **Name**: Descriptive PascalCase text indicating policy focus.

Examples of compliant GPOs:
* `GPO_T0_Hardening_DomainControllers`
* `GPO_T2_Config_WorkstationIsolation`
* `GPO_Global_Hardening_DefaultDomain`

#### 3. GPO Description Metadata Template
Every GPO must have its **Description** field populated in `gpmc.msc` properties using the following structured template. This template uses a YAML-compatible layout to support programmatic validation:

```yaml
---
RequirementID: [ID of corresponding hardening control, e.g., REQ-OPS-007]
Owner: [Administrative team/role responsible, e.g., Domain Admins]
CreatedBy: [Account name of creator, e.g., a0-sysadmin]
CreatedDate: [YYYY-MM-DD]
LastModifiedBy: [Account name of editor, e.g., a0-sysadmin]
LastModifiedDate: [YYYY-MM-DD]
Purpose: [A clear, concise summary of the settings applied and their intent]
ApprovalRef: [Change management ticket or authorization reference, e.g., CR-84920]
Tier: [T0 / T1 / T2 / Global]
---
```

#### 4. Active Directory Account Naming Scheme
Configure and provision accounts using standardized prefixes:
* **Tier 0 Administrative Accounts**: Prefix `a0-` (e.g., `a0-florian`).
* **Tier 1 Administrative Accounts**: Prefix `a1-` (e.g., `a1-florian`).
* **Tier 2 Administrative Accounts**: Prefix `a2-` (e.g., `a2-florian`).
* **Tier 0 Service Accounts / gMSAs**: Prefix `s0-` / `g0-` (e.g., `s0-backup`, `g0-adbackup$`).
* **Tier 1 Service Accounts / gMSAs**: Prefix `s1-` / `g1-` (e.g., `s1-sql`, `g1-sqlservice$`).
* **Tier 2 Service Accounts / gMSAs**: Prefix `s2-` / `g2-` (e.g., `s2-print`, `g2-printservice$`).
* **Emergency (Break-Glass) Accounts**: Prefix `bg-` (e.g., `bg-admin1`).

---

### Option B: PowerShell & Administrative Scripting (Remediation / Auditing)

#### 1. Configuring GPO Description Metadata
Use the following remediation script to programmatically write or update the structured metadata template to a specified GPO's description field.

[Download Script: Configure-GPODescription.ps1](implementation_scripts/Configure-GPODescription.ps1)

```powershell
# Configure-GPODescription.ps1
# Description: Configures structured metadata in a GPO's description field.

param (
    [Parameter(Mandatory = $true)]
    [string]$GPOName,

    [Parameter(Mandatory = $true)]
    [string]$RequirementID,

    [Parameter(Mandatory = $true)]
    [string]$Owner,

    [Parameter(Mandatory = $true)]
    [string]$CreatedBy,

    [Parameter(Mandatory = $true)]
    [string]$ApprovalRef,

    [Parameter(Mandatory = $true)]
    [ValidateSet("T0", "T1", "T2", "Global")]
    [string]$Tier,

    [Parameter(Mandatory = $true)]
    [string]$Purpose
)

Import-Module GroupPolicy -ErrorAction SilentlyContinue

Write-Host "--- Configuring Structured GPO Description Metadata ---" -ForegroundColor Cyan

# Verify if GPO exists
$gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if (-not $gpo) {
    Write-Error "Group Policy Object '$GPOName' was not found in the domain."
    exit 1
}

$CurrentDate = Get-Date -Format "yyyy-MM-dd"

# Build YAML-style metadata string
$DescriptionText = @"
---
RequirementID: $RequirementID
Owner: $Owner
CreatedBy: $CreatedBy
CreatedDate: $CurrentDate
LastModifiedBy: $CreatedBy
LastModifiedDate: $CurrentDate
Purpose: $Purpose
ApprovalRef: $ApprovalRef
Tier: $Tier
---
"@

try {
    # Set the GPO description
    Set-GPO -Name $GPOName -Description $DescriptionText -ErrorAction Stop
    Write-Host "[+] Successfully configured description metadata for GPO: $GPOName" -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Failed to update description for GPO '$GPOName'. Error: $($_.Exception.Message)"
    exit 1
}
```

*To verify directory alignment and find non-compliant OUs, GPOs, and Accounts:*

[Download Script: Audit-NamingConventions.ps1](audit_scripts/Audit-NamingConventions.ps1)

```powershell
# Audit-NamingConventions.ps1
# Description: Audits GPOs, OUs, and User Accounts for compliance with standard naming conventions and metadata description templates.

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

Write-Host "--- Auditing Active Directory Naming Conventions & Metadata ---" -ForegroundColor Cyan

$Compliant = $true

# Define Regex Patterns
$gpoNameRegex = "^GPO_(T[0-2]|Global)_(Hardening|Config|Restricted|Software)_[A-Za-z0-9]+$"
$ouNameRegex  = "^(T[0-2]-(Computers|Users|Groups|ServiceAccounts|Servers|Endpoints|Admins)-[A-Za-z0-9-]+|Domain Controllers|System|Builtin|ForeignSecurityPrincipals|LostAndFound|NTDS Quotas|Program Data)$"

# 1. Audit GPO Names and Description Fields
Write-Host "`n[+] Checking Group Policy Objects..." -ForegroundColor Yellow
try {
    $gpos = Get-GPO -All -ErrorAction Stop
    foreach ($gpo in $gpos) {
        $gpoName = $gpo.DisplayName
        
        # Check Name format
        if ($gpoName -notmatch $gpoNameRegex) {
            Write-Host "  [-] NON-COMPLIANT GPO NAME: '$gpoName' (does not match expected structure)" -ForegroundColor Red
            $Compliant = $false
        } else {
            Write-Host "  [+] GPO Name OK: '$gpoName'" -ForegroundColor Green
        }

        # Check Description metadata
        $desc = $gpo.Description
        if ([string]::IsNullOrEmpty($desc)) {
            Write-Host "  [-] NON-COMPLIANT GPO DESCRIPTION: '$gpoName' (Description field is empty)" -ForegroundColor Red
            $Compliant = $false
        } else {
            # Verify YAML structure has key metadata fields
            $hasReqId = $desc -match "RequirementID:"
            $hasOwner = $desc -match "Owner:"
            $hasTier  = $desc -match "Tier:"
            $hasPurpose = $desc -match "Purpose:"

            if ($hasReqId -and $hasOwner -and $hasTier -and $hasPurpose) {
                Write-Host "  [+] GPO Description Template OK: '$gpoName'" -ForegroundColor Green
            } else {
                Write-Host "  [-] NON-COMPLIANT GPO DESCRIPTION FORMAT: '$gpoName' (Structured fields are missing or malformed)" -ForegroundColor Red
                $Compliant = $false
            }
        }
    }
} catch {
    Write-Warning "Could not retrieve GPOs from domain. Ensure GPMC RSAT tools are installed and domain is reachable."
}

# 2. Audit Organizational Units
Write-Host "`n[+] Checking Organizational Units (OUs)..." -ForegroundColor Yellow
try {
    $ous = Get-ADOrganizationalUnit -Filter * -ErrorAction Stop
    foreach ($ou in $ous) {
        $ouName = $ou.Name
        if ($ouName -notmatch $ouNameRegex) {
            Write-Host "  [-] NON-COMPLIANT OU NAME: '$ouName' (DistinguishedName: $($ou.DistinguishedName))" -ForegroundColor Red
            $Compliant = $false
        } else {
            Write-Host "  [+] OU Name OK: '$ouName'" -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Could not retrieve OUs from Active Directory. Ensure AD RSAT tools are installed."
}

# 3. Audit Account Naming Conventions (Tiered / Service / Emergency)
Write-Host "`n[+] Checking Account Naming Conventions..." -ForegroundColor Yellow
try {
    # Check Administrative Group memberships to see if administrative accounts are properly prefixed
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    foreach ($group in $privilegedGroups) {
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            if ($member.objectClass -eq "user") {
                $sam = $member.SamAccountName
                # Tier 0 admins must have 'a0-' or 'bg-' or be standard default Administrator
                if ($sam -ne "Administrator" -and $sam -notlike "a0-*" -and $sam -notlike "bg-*") {
                    Write-Host "  [-] NON-COMPLIANT TIER 0 ACCOUNT NAME: '$sam' (Member of privileged group: $group, lacks 'a0-' or 'bg-' prefix)" -ForegroundColor Red
                    $Compliant = $false
                } else {
                    Write-Host "  [+] Admin Account Prefix OK: '$sam' ($group)" -ForegroundColor Green
                }
            }
        }
    }
    
    # Audit Service Accounts and gMSAs
    $serviceAccounts = Get-ADServiceAccount -Filter * -ErrorAction SilentlyContinue
    foreach ($sa in $serviceAccounts) {
        $sam = $sa.SamAccountName
        if ($sam -notlike "g0-*" -and $sam -notlike "g1-*" -and $sam -notlike "g2-*") {
            Write-Host "  [-] NON-COMPLIANT gMSA NAME: '$sam' (lacks 'g0-', 'g1-', or 'g2-' prefix)" -ForegroundColor Red
            $Compliant = $false
        } else {
            Write-Host "  [+] gMSA Prefix OK: '$sam'" -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Could not query account or group memberships. Ensure AD RSAT tools are installed and domain is reachable."
}

# 4. Final Compliance Verdict
if ($Compliant) {
    Write-Host "`nStatus: Compliant. GPOs, OUs, and Accounts conform to standard conventions." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nStatus: Non-Compliant. Naming conventions drift detected." -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R12 (Naming and description convention of GPOs)
* **CIS Microsoft Windows Server 2016 Benchmark v2.0.0**: Section 1.1.1 (Security policy and resource management)
* **Microsoft Security Best Practices**: Administrative Account Lifecycle and Group Policy Management Strategy
