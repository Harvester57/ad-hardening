# Get-ProhibitWcnWizardsStatus.ps1
# Description: Audits registry configuration of DisableWcnUi on Domain Controllers.

Write-Host "--- Auditing DisableWcnUi Status ---" -ForegroundColor Cyan

$WcnUiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
$ExpectedValue = 1

if (Test-Path -Path $WcnUiPath) {
    $Reg = Get-ItemProperty -Path $WcnUiPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.DisableWcnUi

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] DisableWcnUi: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] DisableWcnUi: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] WCN UI Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
