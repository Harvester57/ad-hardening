# Test-LocalLogonRestrictions.ps1
# Audits local security policies to check if SeDeny rights are populated.

Write-Host "--- Auditing Local User Rights Assignments ---" -ForegroundColor Cyan

$tempDir = [System.IO.Path]::GetTempPath()
$secConfigPath = Join-Path $tempDir "sec_audit.inf"

# Export current configuration
secedit /export /cfg $secConfigPath /areas USER_RIGHTS /quiet

$configContent = Get-Content -Path $secConfigPath
$PoliciesToTest = @(
    "SeDenyInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight"
)

foreach ($policy in $PoliciesToTest) {
    $match = $configContent | Where-Object { $_ -match "^$policy\s*=" }
    if ($match) {
        # Check if it contains domain admin or other groups
        Write-Host "    - Policy '$policy' is configured: $match" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: Policy '$policy' is not defined (No accounts denied)." -ForegroundColor Red
    }
}

if (Test-Path $secConfigPath) { Remove-Item $secConfigPath -Force }
