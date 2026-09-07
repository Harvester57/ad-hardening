# Harden-DnsServerConfiguration.ps1
# Description: Hardens Microsoft DNS on Domain Controllers by removing ServerLevelPluginDll backdoors, enforcing Secure Dynamic Updates on AD-integrated zones, and verifying DnsAdmins membership.

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module DnsServer -ErrorAction SilentlyContinue

Write-Host "Applying hardening requirement: Harden Microsoft DNS AD Container..." -ForegroundColor Cyan

# 1. Clean up ServerLevelPluginDll Registry Key
$RegPath = "HKLM:\System\CurrentControlSet\Services\DNS\Parameters"
$ValueName = "ServerLevelPluginDll"

if (Test-Path -Path $RegPath) {
    $PluginDll = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $PluginDll -and $null -ne $PluginDll.ServerLevelPluginDll -and $PluginDll.ServerLevelPluginDll -ne "") {
        Write-Host "[-] WARNING: Potentially unauthorized DNS plugin detected: $($PluginDll.ServerLevelPluginDll)" -ForegroundColor Yellow
        Remove-ItemProperty -Path $RegPath -Name $ValueName -Force -ErrorAction Stop
        Write-Host "[+] ServerLevelPluginDll registry parameter removed successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] No ServerLevelPluginDll registry parameter found (clean configuration)." -ForegroundColor Green
    }
}

# 2. Enforce Secure Dynamic Updates on Active Directory-Integrated Zones
if (Get-Command -Name "Get-DnsServerZone" -ErrorAction SilentlyContinue) {
    Write-Host "Checking Dynamic Update settings on AD-integrated DNS zones..." -ForegroundColor White
    $Zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsDsIntegrated -eq $true -and $_.ZoneType -eq "Primary" }
    foreach ($Zone in $Zones) {
        if ($Zone.DynamicUpdate -ne "Secure") {
            Write-Host "[-] Zone '$($Zone.ZoneName)' has DynamicUpdate set to '$($Zone.DynamicUpdate)'. Enforcing Secure only..." -ForegroundColor Yellow
            Set-DnsServerPrimaryZone -Name $Zone.ZoneName -DynamicUpdate "Secure" -ErrorAction SilentlyContinue
            Write-Host "[+] Zone '$($Zone.ZoneName)' DynamicUpdate set to Secure." -ForegroundColor Green
        } else {
            Write-Host "[+] Zone '$($Zone.ZoneName)' DynamicUpdate is Secure." -ForegroundColor Green
        }
    }
}

# 3. Audit and Alert on DnsAdmins Membership
if (Get-Command -Name "Get-ADGroup" -ErrorAction SilentlyContinue) {
    $DnsAdminsGroup = Get-ADGroup -Filter "Name -eq 'DnsAdmins'" -ErrorAction SilentlyContinue

    if ($null -ne $DnsAdminsGroup) {
        $Members = Get-ADGroupMember -Identity $DnsAdminsGroup -ErrorAction SilentlyContinue
        if ($null -ne $Members -and @($Members).Count -gt 0) {
            Write-Host "[-] WARNING: The DnsAdmins group contains active members. Ensure all members are verified Tier 0 identities:" -ForegroundColor Yellow
            foreach ($Member in $Members) {
                Write-Host "    - Member: $($Member.SamAccountName) ($($Member.objectClass))" -ForegroundColor White
            }
        } else {
            Write-Host "[+] The DnsAdmins group is empty (recommended Tier 0 posture)." -ForegroundColor Green
        }
    }
}
