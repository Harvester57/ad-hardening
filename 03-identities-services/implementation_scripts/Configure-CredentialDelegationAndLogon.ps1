# Configure-CredentialDelegationAndLogon.ps1
# Description: Hardens logon screen user enumeration, CredSSP encryption oracle remediation, and remote host non-exportable credentials delegation.

Write-Host "Applying logon screen and credentials delegation registry controls..." -ForegroundColor Cyan

# 1. Disable Logon Screen User Enumeration
$SystemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPath -Name "EnumerateLocalUsers" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Logon screen local user enumeration disabled." -ForegroundColor Green

# 2. Enforce CredSSP Encryption Oracle Remediation
$CredSspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $CredSspPath)) {
    New-Item -Path $CredSspPath -Force | Out-Null
}
Set-ItemProperty -Path $CredSspPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] CredSSP Encryption Oracle Remediation configured to Force Updated Clients." -ForegroundColor Green

# 3. Remote Host Allows Delegation of Non-Exportable Credentials
$DelegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if (-not (Test-Path $DelegPath)) {
    New-Item -Path $DelegPath -Force | Out-Null
}
Set-ItemProperty -Path $DelegPath -Name "AllowProtectedCreds" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Delegation of non-exportable credentials enabled." -ForegroundColor Green
