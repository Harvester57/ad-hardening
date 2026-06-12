# Test-IPsecDomainIsolation.ps1
# Checks the state of local IPsec Connection Security Rules.

Write-Host "Auditing IPsec Connection Security Rules..." -ForegroundColor Cyan

$Rules = Get-NetIPsecRule -ErrorAction SilentlyContinue

if ($null -eq $Rules -or $Rules.Count -eq 0) {
    Write-Host "    - No IPsec Connection Security Rules found (Non-Compliant)." -ForegroundColor Red
} else {
    foreach ($Rule in $Rules) {
        $Security = $Rule.InboundSecurity
        $Enabled = $Rule.Enabled
        
        $Color = "Red"
        if ($Enabled -eq $true) {
            if ($Security -eq "Request" -or $Security -eq "Require") {
                $Color = "Green"
            }
        }
        
        Write-Host "    - Rule: $($Rule.DisplayName) | Enabled: $($Enabled) | InboundSecurity: $($Security)" -ForegroundColor $Color
    }
}
