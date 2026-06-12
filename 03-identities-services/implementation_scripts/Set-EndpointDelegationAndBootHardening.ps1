# Set-EndpointDelegationAndBootHardening.ps1
# Description: Hardens Point and Print restrictions, ELAM policies, logon screen enumeration, and credentials delegation.

Write-Host "Applying printer, boot driver, logon screen, and delegation registry controls..." -ForegroundColor Cyan

# 1. Limit Print Driver Installation to Administrators
$PrinterPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $PrinterPath)) {
    New-Item -Path $PrinterPath -Force | Out-Null
}
Set-ItemProperty -Path $PrinterPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Print driver installation restricted to Administrators." -ForegroundColor Green

# 2. Configure ELAM Driver Load Policy
$ElamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $ElamPath)) {
    New-Item -Path $ElamPath -Force | Out-Null
}
Set-ItemProperty -Path $ElamPath -Name "DriverLoadPolicy" -Value 3 -Type DWord -ErrorAction Stop
Write-Host "[+] ELAM Boot-Start driver initialization policy set to Good, unknown and bad but critical." -ForegroundColor Green

# 3. Disable Logon Screen User Enumeration
$SystemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPath -Name "EnumerateLocalUsers" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Logon screen local user enumeration disabled." -ForegroundColor Green

# 4. Enforce CredSSP Encryption Oracle Remediation
$CredSspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $CredSspPath)) {
    New-Item -Path $CredSspPath -Force | Out-Null
}
Set-ItemProperty -Path $CredSspPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] CredSSP Encryption Oracle Remediation configured to Force Updated Clients." -ForegroundColor Green

# 5. Remote Host Allows Delegation of Non-Exportable Credentials
$DelegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if (-not (Test-Path $DelegPath)) {
    New-Item -Path $DelegPath -Force | Out-Null
}
Set-ItemProperty -Path $DelegPath -Name "AllowProtectedCreds" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Delegation of non-exportable credentials enabled." -ForegroundColor Green
