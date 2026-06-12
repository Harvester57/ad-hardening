# Get-RestrictNTLMStatus.ps1
# Description: Audits the registry configuration for NTLM auditing and restrictions.

Write-Host "--- Auditing NTLM Restrictions ---" -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

if (Test-Path $LsaPath) {
    $AuditRecv = Get-ItemProperty -Path $LsaPath -Name "AuditReceivingNTLMTraffic" -ErrorAction SilentlyContinue
    if ($AuditRecv) {
        Write-Host "[+] AuditReceivingNTLMTraffic is set to $($AuditRecv.AuditReceivingNTLMTraffic) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: AuditReceivingNTLMTraffic is not configured." -ForegroundColor Red
    }

    $RestrictRecv = Get-ItemProperty -Path $LsaPath -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue
    if ($RestrictRecv) {
        Write-Host "[+] RestrictReceivingNTLMTraffic is set to $($RestrictRecv.RestrictReceivingNTLMTraffic) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictReceivingNTLMTraffic is not configured." -ForegroundColor Red
    }

    $RestrictSend = Get-ItemProperty -Path $LsaPath -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
    if ($RestrictSend) {
        Write-Host "[+] RestrictSendingNTLMTraffic is set to $($RestrictSend.RestrictSendingNTLMTraffic) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictSendingNTLMTraffic is not configured." -ForegroundColor Red
    }
} else {
    Write-Host "[!] LSA MSV1_0 path does not exist." -ForegroundColor Red
}

if (Test-Path $NetlogonPath) {
    $AuditDomain = Get-ItemProperty -Path $NetlogonPath -Name "AuditNTLMInDomain" -ErrorAction SilentlyContinue
    if ($AuditDomain) {
        Write-Host "[+] AuditNTLMInDomain is set to $($AuditDomain.AuditNTLMInDomain) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: AuditNTLMInDomain is not configured." -ForegroundColor Red
    }

    $RestrictDomain = Get-ItemProperty -Path $NetlogonPath -Name "RestrictNTLMInDomain" -ErrorAction SilentlyContinue
    if ($RestrictDomain) {
        Write-Host "[+] RestrictNTLMInDomain is set to $($RestrictDomain.RestrictNTLMInDomain) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictNTLMInDomain is not configured." -ForegroundColor Red
    }
} else {
    Write-Host "[!] Netlogon Parameters path does not exist." -ForegroundColor Red
}
