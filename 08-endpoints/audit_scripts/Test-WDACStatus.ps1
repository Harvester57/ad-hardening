# Test-WDACStatus.ps1
# Audits the local system to check if Code Integrity policies are active.

Write-Host "--- Auditing WDAC Activation State ---" -ForegroundColor Cyan

try {
    # Query WMI class for Code Integrity status
    $CI = Get-CimInstance -Namespace "Root\Microsoft\Windows\CI" -ClassName "MSFT_Sipolicy" -ErrorAction Stop
    Write-Host "`n[+] Found $($CI.Count) active Code Integrity policies." -ForegroundColor Yellow
    
    foreach ($Policy in $CI) {
        # FriendlyName, PolicyID, Enforcer properties
        # FriendlyName or PolicyName depending on OS build
        Write-Host "    - Policy: $($Policy.FriendlyName) | ID: $($Policy.PolicyID) | Enforced: $($Policy.EnforcementMode)" -ForegroundColor Green
    }
} catch {
    Write-Host "    - VULNERABLE: No active Code Integrity / WDAC policies detected on the local system." -ForegroundColor Red
}
