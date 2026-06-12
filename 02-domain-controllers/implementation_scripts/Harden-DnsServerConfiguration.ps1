# Harden-DnsServerConfiguration.ps1
# Description: Deletes any ServerLevelPluginDll entry to block DNS DLL hijacking, and checks DnsAdmins group.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Harden Microsoft DNS AD Container..." -ForegroundColor Cyan

# 1. Clean up ServerLevelPluginDll Registry Key
$RegPath = "HKLM:\System\CurrentControlSet\Services\DNS\Parameters"
$ValueName = "ServerLevelPluginDll"

if (Test-Path $RegPath) {
    $PluginDll = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $PluginDll) {
        Write-Host "[-] WARNING: Potentially unauthorized DNS plugin detected: $($PluginDll.ServerLevelPluginDll)" -ForegroundColor Yellow
        Remove-ItemProperty -Path $RegPath -Name $ValueName -Force -ErrorAction Stop
        Write-Host "[+] ServerLevelPluginDll registry parameter removed successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] No ServerLevelPluginDll registry parameter found (clean configuration)." -ForegroundColor Green
    }
}

# 2. Audit DnsAdmins Membership
$DnsAdminsGroup = Get-ADGroup -Filter "Name -eq 'DnsAdmins'" -ErrorAction SilentlyContinue

if ($null -ne $DnsAdminsGroup) {
    $Members = Get-ADGroupMember -Identity $DnsAdminsGroup
    if ($Members.Count -gt 0) {
        Write-Host "[-] WARNING: The DnsAdmins group contains active members. Please verify that all members are Tier 0 identities." -ForegroundColor Yellow
        foreach ($Member in $Members) {
            Write-Host "    - Member: $($Member.SamAccountName) ($($Member.objectClass))" -ForegroundColor White
        }
    } else {
        Write-Host "[+] The DnsAdmins group is empty (recommended)." -ForegroundColor Green
    }
}
