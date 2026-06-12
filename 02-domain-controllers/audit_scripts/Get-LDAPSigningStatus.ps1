# Get-LDAPSigningStatus.ps1
# Description: Audits the LDAP server signing configuration in the registry.

Write-Host "--- Auditing LDAP Server Signing ---" -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
$ntdsReg = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

if ($ntdsReg) {
    $integrityVal = $ntdsReg.LDAPServerIntegrity
    if ($integrityVal -eq 2) {
        Write-Host "[+] LDAP Server Signing is secure. LDAPServerIntegrity is set to $($integrityVal) (Require Signing)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: LDAPServerIntegrity is set to $($integrityVal) (Required: 2)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: LDAPServerIntegrity registry value is missing. The system uses default negotiation (allows unsigned connections)." -ForegroundColor Red
}
