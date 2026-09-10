# Get-EndAccountBlockMsaStatus.ps1
# Description: Audits consumer Microsoft account blocking status on Endpoints.

Write-Host "--- Auditing Endpoint Consumer Microsoft Account Restrictions ---" -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"

if (-not (Test-Path -Path $MsaPath)) {
    Write-Host "    [!] MISSING KEY: $MsaPath" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}

$Val = (Get-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -ErrorAction SilentlyContinue).DisableUserAuth

if ($null -ne $Val -and $Val -eq 1) {
    Write-Host "    [+] DisableUserAuth is set to 1 (Enabled - Secure)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: DisableUserAuth is '$Val' (Expected: 1)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
