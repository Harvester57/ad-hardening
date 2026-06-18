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
