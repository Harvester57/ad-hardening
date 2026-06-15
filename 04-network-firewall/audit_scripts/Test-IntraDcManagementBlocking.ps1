# Test-IntraDcManagementBlocking.ps1
# Description: Audits if management traffic from other Domain Controllers is blocked.

Write-Host "Auditing Intra-DC management blocking configurations..." -ForegroundColor Cyan

$vulnerable = $false
$BlockRules = @(
    "AD-Block-IntraDC-RDP",
    "AD-Block-IntraDC-WinRM-HTTP",
    "AD-Block-IntraDC-WinRM-HTTPS",
    "AD-Block-IntraDC-WMI",
    "AD-Block-IntraDC-ADWS"
)

foreach ($Name in $BlockRules) {
    $Rule = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($Rule) {
        if ($Rule.Enabled -eq $true -and $Rule.Action -eq "Block") {
            Write-Host "[+] Rule $($Name) is active and configured to Block." -ForegroundColor Green
        } else {
            Write-Host "[!] NON-COMPLIANT: Rule $($Name) exists but is disabled or not set to Block." -ForegroundColor Red
            $vulnerable = $true
        }
    } else {
        Write-Host "[!] NON-COMPLIANT: Block rule $($Name) is missing." -ForegroundColor Red
        $vulnerable = $true
    }
}

if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
