# Get-DnsAuditStatus.ps1
# Description: Queries the DNS registry parameter settings, AD container ACLs, dynamic updates, and homoglyph records.

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module DnsServer -ErrorAction SilentlyContinue

Write-Host "--- Auditing DNS Security Parameters ---" -ForegroundColor Cyan

$isVulnerable = $false

# 1. Check ServerLevelPluginDll Registry Backdoor
$RegPath = "HKLM:\System\CurrentControlSet\Services\DNS\Parameters"
$ValueName = "ServerLevelPluginDll"

if (Test-Path -Path $RegPath) {
    $Val = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Val -and $null -ne $Val.ServerLevelPluginDll -and $Val.ServerLevelPluginDll -ne "") {
        Write-Host "[!] VULNERABLE: ServerLevelPluginDll is configured: $($Val.ServerLevelPluginDll)" -ForegroundColor Red
        $isVulnerable = $true
    } else {
        Write-Host "[+] ServerLevelPluginDll: Not configured (Secure)." -ForegroundColor Green
    }
}

# 2. Check DnsAdmins Membership
if (Get-Command -Name "Get-ADGroup" -ErrorAction SilentlyContinue) {
    $DnsAdminsGroup = Get-ADGroup -Filter "Name -eq 'DnsAdmins'" -ErrorAction SilentlyContinue
    if ($null -ne $DnsAdminsGroup) {
        $Members = Get-ADGroupMember -Identity $DnsAdminsGroup -ErrorAction SilentlyContinue
        if ($null -ne $Members -and @($Members).Count -gt 0) {
            Write-Host "[-] WARNING: DnsAdmins group contains active members (Verify Tier 0 boundary):" -ForegroundColor Yellow
            foreach ($Member in $Members) {
                Write-Host "    - Member: $($Member.SamAccountName)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[+] DnsAdmins group is empty (Secure)." -ForegroundColor Green
        }
    }
}

# 3. Check Dynamic Updates on AD-Integrated Zones
if (Get-Command -Name "Get-DnsServerZone" -ErrorAction SilentlyContinue) {
    $Zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsDsIntegrated -eq $true -and $_.ZoneType -eq "Primary" }
    foreach ($Zone in $Zones) {
        if ($Zone.DynamicUpdate -ne "Secure") {
            Write-Host "[!] VULNERABLE: Zone '$($Zone.ZoneName)' DynamicUpdate is set to '$($Zone.DynamicUpdate)' (Expected: Secure)." -ForegroundColor Red
            $isVulnerable = $true
        } else {
            Write-Host "[+] Zone '$($Zone.ZoneName)': DynamicUpdate is Secure." -ForegroundColor Green
        }
    }
}

# 4. Check AD Container Write ACLs (System, DomainDnsZones, ForestDnsZones)
if (Get-Command -Name "Get-ADRootDSE" -ErrorAction SilentlyContinue) {
    $RootDSE = Get-ADRootDSE -ErrorAction SilentlyContinue
    if ($null -ne $RootDSE) {
        $DomainDN = $RootDSE.defaultNamingContext
        $RootDomainDN = $RootDSE.rootDomainNamingContext

        $Containers = @(
            "AD:\CN=MicrosoftDNS,CN=System,$DomainDN",
            "AD:\CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDN",
            "AD:\CN=MicrosoftDNS,DC=ForestDnsZones,$RootDomainDN"
        )

        $AllowedTrustees = @(
            "NT AUTHORITY\SYSTEM",
            "BUILTIN\Administrators",
            "Enterprise Domain Controllers",
            "Domain Admins",
            "Enterprise Admins"
        )

        foreach ($ContainerPath in $Containers) {
            if (Test-Path -Path $ContainerPath) {
                Write-Host "Reviewing AD container permissions: $($ContainerPath)..." -ForegroundColor White
                $Acl = Get-Acl -Path $ContainerPath -ErrorAction SilentlyContinue
                if ($null -ne $Acl) {
                    foreach ($Rule in $Acl.Access) {
                        $Identity = $Rule.IdentityReference.Value
                        $Rights = $Rule.ActiveDirectoryRights

                        if ($Rights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite") {
                            $IsAllowed = $false
                            foreach ($Allowed in $AllowedTrustees) {
                                if ($Identity -match [regex]::Escape($Allowed)) {
                                    $IsAllowed = $true
                                    break
                                }
                            }

                            if (-not $IsAllowed) {
                                Write-Host "[!] VULNERABLE: Unauthorized write permission on $($ContainerPath) - Trustee: $($Identity) - Rights: $($Rights)" -ForegroundColor Red
                                $isVulnerable = $true
                            }
                        }
                    }
                }
            }
        }
    }
}

# 5. Check for Non-ASCII / Unicode Homoglyph Records (Ghost-SPN / CVE-2025-58726)
if (Get-Command -Name "Get-DnsServerResourceRecord" -ErrorAction SilentlyContinue) {
    $Zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsDsIntegrated -eq $true -and $_.ZoneType -eq "Primary" }
    foreach ($Zone in $Zones) {
        $Records = Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName -ErrorAction SilentlyContinue
        if ($null -ne $Records) {
            foreach ($Record in $Records) {
                if ($Record.HostName -match "[^\x20-\x7E]") {
                    Write-Host "[!] VULNERABLE: Potential Ghost-SPN homoglyph record detected in zone '$($Zone.ZoneName)': $($Record.HostName)" -ForegroundColor Red
                    $isVulnerable = $true
                }
            }
        }
    }
}

# Final Compliance Verdict
if ($isVulnerable) {
    Write-Host "[!] Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "[+] Audit Result: SECURE" -ForegroundColor Green
}
