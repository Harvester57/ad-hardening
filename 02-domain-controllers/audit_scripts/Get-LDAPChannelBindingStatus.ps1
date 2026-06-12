# Get-LDAPChannelBindingStatus.ps1
# Description: Audits the LDAP Channel Binding Token configuration in the registry.

Write-Host "--- Auditing LDAP Channel Binding ---" -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
$ntdsReg = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue

if ($ntdsReg) {
    $cbtVal = $ntdsReg.LdapEnforceChannelBinding
    if ($cbtVal -eq 2) {
        Write-Host "[+] LDAP Channel Binding is secure. LdapEnforceChannelBinding is set to $($cbtVal) (Always)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: LdapEnforceChannelBinding is set to $($cbtVal) (Required: 2)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: LdapEnforceChannelBinding registry value is missing. The system uses default settings (does not enforce CBT)." -ForegroundColor Red
}
