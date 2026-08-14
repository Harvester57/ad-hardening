# Get-EndAccountBlockMsaStatus.ps1
Write-Host "--- Auditing Endpoint Consumer Microsoft Account Restrictions ---" -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
$Val = (Get-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -ErrorAction SilentlyContinue).DisableUserAuth

if ($null -ne $Val -and $Val -eq 1) {
    Write-Host "    [+] DisableUserAuth is set to 1 (Enabled)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: DisableUserAuth is '$Val' (Expected: 1)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
