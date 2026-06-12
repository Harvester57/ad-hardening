# Set-IPsecDomainIsolation.ps1
# Configures local IPsec Connection Security Rules requesting Kerberos V5 authentication.

Write-Host "Configuring IPsec Connection Security Rules..." -ForegroundColor Cyan

# Check if the rule already exists
$RuleName = "Hardening: IPsec Domain Isolation"
$ExistingRule = Get-NetIPsecRule -DisplayName $RuleName -ErrorAction SilentlyContinue

if ($null -eq $ExistingRule) {
    # Create IPsec Isolation rule requesting authentication
    New-NetIPsecRule -DisplayName $RuleName `
        -InboundSecurity Request `
        -OutboundSecurity Request `
        -Phase1AuthSet "ComputerKerberos" `
        -Enabled True | Out-Null
        
    Write-Host "IPsec Domain Isolation rule created successfully." -ForegroundColor Green
} else {
    Set-NetIPsecRule -DisplayName $RuleName -InboundSecurity Request -OutboundSecurity Request -Enabled True | Out-Null
    Write-Host "IPsec Domain Isolation rule updated/verified." -ForegroundColor Gray
}
