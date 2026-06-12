# Audit-GPOPrecedence.ps1
# Description: Verifies that a dedicated hardening GPO exists with higher precedence than Default DC Policy.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "--- Auditing Domain Controllers OU GPO Precedence ---" -ForegroundColor Cyan

$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"

try {
    $OUInfo = Get-GPInheritance -Target $DCOUDN -ErrorAction Stop
    
    Write-Host "`nLinked GPOs on Domain Controllers OU:" -ForegroundColor Yellow
    $HardeningGPOFound = $false
    $HardeningOrder = 999
    $DefaultDCOrder = 999
    
    foreach ($link in $OUInfo.GpoLinks) {
        $status = if ($link.Enabled) { "Enabled" } else { "Disabled" }
        Write-Host "    - Link Order: $($link.Order) | GPO Name: $($link.DisplayName) | Status: $status" -ForegroundColor White
        
        if ($link.DisplayName -like "*Hardening*" -and $link.Enabled) {
            $HardeningGPOFound = $true
            $HardeningOrder = $link.Order
        }
        if ($link.DisplayName -eq "Default Domain Controllers Policy") {
            $DefaultDCOrder = $link.Order
        }
    }
    
    if ($HardeningGPOFound -and $HardeningOrder -lt $DefaultDCOrder) {
        Write-Host "`nStatus: Compliant. Custom hardening GPO has higher precedence (Order $HardeningOrder) than Default Domain Controllers Policy (Order $DefaultDCOrder)." -ForegroundColor Green
    } else {
        Write-Host "`nVULNERABLE: No active dedicated hardening GPO found with higher precedence than the Default Domain Controllers Policy." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not retrieve GPO information for Domain Controllers OU. Error: $($_.Exception.Message)" -ForegroundColor Red
}
