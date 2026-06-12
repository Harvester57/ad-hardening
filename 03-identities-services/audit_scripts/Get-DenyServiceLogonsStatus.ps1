# Get-DenyServiceLogonsStatus.ps1
# Description: Audits the Deny logon rights configurations locally.

Write-Host "--- Auditing Deny Logon Rights ---" -ForegroundColor Cyan

$SecCfg = "$($env:temp)\auditpolicy.inf"
secedit /export /cfg $SecCfg /quiet

$cfgContent = Get-Content -Path $SecCfg
$denyLocal = $cfgContent | Where-Object { $_ -like "SeDenyInteractiveLogonRight*" }
$denyRdp = $cfgContent | Where-Object { $_ -like "SeDenyRemoteInteractiveLogonRight*" }

Write-Host "[+] Local Deny Logon Rights settings:" -ForegroundColor Green
if ($denyLocal) {
    Write-Host "    - $denyLocal" -ForegroundColor White
} else {
    Write-Host "    - SeDenyInteractiveLogonRight is not configured." -ForegroundColor Yellow
}

if ($denyRdp) {
    Write-Host "    - $denyRdp" -ForegroundColor White
} else {
    Write-Host "    - SeDenyRemoteInteractiveLogonRight is not configured." -ForegroundColor Yellow
}

Remove-Item -Path $SecCfg -Force
