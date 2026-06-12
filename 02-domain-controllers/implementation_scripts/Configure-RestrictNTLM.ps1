# Configure-RestrictNTLM.ps1
# Description: Configures local registry values to enforce NTLM restrictions and auditing.

Write-Host "Applying hardening requirement: Restrict NTLM..." -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# Ensure LSA MSV1_0 path exists and apply settings
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}

Set-ItemProperty -Path $LsaPath -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "RestrictReceivingNTLMTraffic" -Value 2 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord

# Ensure Netlogon Parameters path exists and apply settings
if (-not (Test-Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}

Set-ItemProperty -Path $NetlogonPath -Name "AuditNTLMInDomain" -Value 7 -Type DWord
Set-ItemProperty -Path $NetlogonPath -Name "RestrictNTLMInDomain" -Value 3 -Type DWord

Write-Host "NTLM restriction registry configurations applied successfully." -ForegroundColor Green
