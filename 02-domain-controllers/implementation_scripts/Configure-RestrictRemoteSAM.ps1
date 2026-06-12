# Configure-RestrictRemoteSAM.ps1
# Description: Restricts remote RPC access to the SAM database to local Administrators.

Write-Host "Applying hardening requirement: Restrict Remote SAM API Access..." -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$sddl = "O:BAG:BAD:(A;;RC;;;BA)"
Set-ItemProperty -Path $regPath -Name "RestrictRemoteSAM" -Value $sddl -Type String
Write-Host "SAM remote API access restricted to Administrators (SDDL applied)." -ForegroundColor Green
