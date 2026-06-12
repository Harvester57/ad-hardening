# Test-AdminProtocolRestrictions.ps1
# Audits local firewall rules for RDP and WinRM to check remote address restrictions.

Write-Host "--- Auditing Administrative Port Firewall Rules ---" -ForegroundColor Cyan

$Rules = @(
    "Remote Desktop - User Mode (TCP-In)",
    "Windows Remote Management (HTTPS-In)",
    "Hardening: Restricted RDP Inbound",
    "Hardening: Restricted WinRM HTTPS Inbound"
)

foreach ($RuleName in $Rules) {
    $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($Rule) {
        $Address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule
        $color = if ($Address.RemoteAddress -ne "Any" -and $Address.RemoteAddress -ne "") { "Green" } else { "Red" }
        Write-Host "    - Firewall Rule: $($Rule.DisplayName) | Enabled: $($Rule.Enabled) | RemoteAddress Restriction: $($Address.RemoteAddress)" -ForegroundColor $color
    }
}
