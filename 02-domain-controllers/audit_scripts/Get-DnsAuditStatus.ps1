# Get-DnsAuditStatus.ps1
# Description: Queries the DNS registry parameter settings and AD container ACLs.

Import-Module ActiveDirectory

Write-Host "--- Auditing DNS Security Parameters ---" -ForegroundColor Cyan

# Check Registry
$RegPath = "HKLM:\System\CurrentControlSet\Services\DNS\Parameters"
$ValueName = "ServerLevelPluginDll"

if (Test-Path $RegPath) {
    $Val = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Val) {
        Write-Host "[!] Danger: ServerLevelPluginDll is configured: $($Val.ServerLevelPluginDll)" -ForegroundColor Red
    } else {
        Write-Host "[+] ServerLevelPluginDll: Not configured (Secure)." -ForegroundColor Green
    }
}

# Check AD Container Write ACLs
$DomainDN = (Get-ADRootDSE).defaultNamingContext
$DnsPath = "AD:\CN=MicrosoftDNS,CN=System,$($DomainDN)"
$Acl = Get-Acl -Path $DnsPath

Write-Host "Reviewing MicrosoftDNS AD container access permissions..." -ForegroundColor White
foreach ($Rule in $Acl.Access) {
    if ($Rule.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite") {
        Write-Host "    - Trustee: $($Rule.IdentityReference.Value) | Rights: $($Rule.ActiveDirectoryRights)" -ForegroundColor Yellow
    }
}
