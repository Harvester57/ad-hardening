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
