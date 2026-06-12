# Test-WorkstationIsolation.ps1
# Audits the presence of isolation blocking rules on local firewall profiles.

Write-Host "Auditing workstation and server peer isolation rules..." -ForegroundColor Cyan

$PortsToVerify = @(445, 3389, 135)
$FailedChecks = 0

foreach ($Port in $PortsToVerify) {
    # Query rules that block inbound traffic on specified ports
    $BlockRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.Direction -eq "Inbound" -and
        $_.Action -eq "Block" -and
        $_.Enabled -eq $true
    }
    
    $HasPortBlock = $false
    foreach ($Rule in $BlockRules) {
        # Check filter associated with the rule to resolve local port
        $Filter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        if ($Filter -and $Filter.LocalPort -eq [string]$Port) {
            $HasPortBlock = $true
        }
    }
    
    if ($HasPortBlock) {
        Write-Host "    - Isolation block rule for Port $($Port): FOUND (Compliant)" -ForegroundColor Green
    } else {
        Write-Host "    - Isolation block rule for Port $($Port): NOT FOUND (Non-Compliant)" -ForegroundColor Red
        $FailedChecks++
    }
}

if ($FailedChecks -eq 0) {
    Write-Host "Audit Result: Peer isolation firewall rules are verified." -ForegroundColor Green
} else {
    Write-Warning "Audit Result: Missing peer isolation rules detected!"
}
