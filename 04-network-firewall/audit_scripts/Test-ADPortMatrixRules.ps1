# Test-ADPortMatrixRules.ps1
# Audits local firewall status and checks if default inbound traffic is blocked.

Write-Host "Auditing local network firewall status..." -ForegroundColor Cyan

# 1. Check Windows Defender Firewall State
$Profiles = Get-NetFirewallProfile
$AllProfilesSecure = $true

foreach ($FwProfile in $Profiles) {
    $Enabled = $FwProfile.Enabled
    $InAction = $FwProfile.DefaultInboundAction
    
    if ($Enabled -eq $true -and $InAction -eq "Block") {
        Write-Host "Profile: $($FwProfile.Name) | Enabled: True | InboundAction: Block" -ForegroundColor Green
    } else {
        Write-Host "Profile: $($FwProfile.Name) | Enabled: $($Enabled) | InboundAction: $($InAction) (INSECURE)" -ForegroundColor Red
        $AllProfilesSecure = $false
    }
}

if ($AllProfilesSecure) {
    Write-Host "Audit Result: Firewall state configuration is compliant." -ForegroundColor Green
} else {
    Write-Warning "Audit Result: Firewall profiles are not fully secured!"
}
