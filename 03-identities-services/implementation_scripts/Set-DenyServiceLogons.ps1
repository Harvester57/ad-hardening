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
