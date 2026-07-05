# Configure-AdvancedAuditPolicies.ps1
# Description: Enforces Advanced Audit Policy Overrides registry value.

$RegPath = "reg:\HKLM\System\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"

Write-Host "Enforcing Advanced Security Audit Policies override settings..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -Force
Write-Host "Advanced Audit Policy overrides enforced successfully." -ForegroundColor Green
