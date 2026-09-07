# [REQ-DC-017] Harden Microsoft DNS AD Container Permissions

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path (Restricted Groups)**: `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups` -> `DnsAdmins` (Members: Empty or Tier 0 administrators only)
  * **GPO Path (Registry Preference)**: `Computer Configuration\Preferences\Windows Settings\Registry` -> Delete `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll`
  * **Active Directory Container Paths**:
    * Legacy Domain Partition: `CN=MicrosoftDNS,CN=System,DC=[Domain]`
    * Domain DNS Application Partition: `CN=MicrosoftDNS,DC=DomainDnsZones,DC=[Domain]`
    * Forest DNS Application Partition: `CN=MicrosoftDNS,DC=ForestDnsZones,DC=[ForestRootDomain]`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`
    * `ServerLevelPluginDll` (Must not exist or be empty)

---

## Rationale
In Active Directory-integrated DNS environments, DNS configuration settings, zones, and resource records are stored directly within the directory and managed via the Microsoft DNS Server service. By default, the built-in `DnsAdmins` group possesses management rights over the DNS service, while standard authenticated domain users possess rights to register new DNS records in AD-integrated zones.

This configuration exposes Domain Controllers and Active Directory to critical attack vectors:
1. **DNS Service DLL Hijacking (`ServerLevelPluginDll`)**: The Microsoft DNS Server management RPC interface permits members of `DnsAdmins` (and accounts with write control over the DNS server configuration) to set the `ServerLevelPluginDll` parameter using `dnscmd.exe /config /serverlevelplugindll \\path\to\malicious.dll`. Because the DNS Server service runs as `NT AUTHORITY\SYSTEM` on Domain Controllers, the service loads this DLL upon restart or server reboot, executing arbitrary code with SYSTEM privileges and granting full Domain Controller compromise (effectively making `DnsAdmins` a Tier 0 equivalent group).
2. **ADIDNS Record Spoofing & Kerberos Reflection (Ghost-SPN)**: In Active Directory Integrated DNS (ADIDNS) zones, the root container DACL grants `Authenticated Users` the `Create all child objects` right (specifically `Create dnsNode objects`) by default. This allows any standard domain user or compromised workstation account to register arbitrary DNS records. Attackers exploit this capability to register Unicode homoglyphs (such as `․` U+2024 or `Ⓡ` U+00AE) matching high-value servers or Domain Controllers. When clients request Kerberos service tickets (TGS-REQ) for an SPN like `HOST/target`, Kerberos linguistic normalization canonicalizes the homoglyph SPN to ASCII (matching the legitimate target), while the Windows DNS client resolves the IP via the attacker's ADIDNS homoglyph record, allowing Kerberos AP-REQ reflection attacks (CVE-2025-58726 / Synacktiv research) and WPAD hijacking.
3. **Partition Directory DACL Tampering**: Modern AD environments store DNS zones across dedicated Application Directory Partitions (`DomainDnsZones` and `ForestDnsZones`) as well as the legacy `CN=System` container. Write access on these containers allows non-Tier 0 identities to modify zone delegations, poison records, manipulate SOA/NS records, or grant themselves persistent backdoor rights.

Enforcing GPO-based restriction on `DnsAdmins`, purging `ServerLevelPluginDll`, enforcing Secure Dynamic Updates, and removing arbitrary child record creation rights on ADIDNS zones ensures that the directory DNS infrastructure strictly adheres to the Tier 0 administrative boundary.

---

## Legacy Impact & Compatibility
* **Delegated DNS Administration**: Delegating DNS administration to non-Tier 0 accounts by placing them in the built-in `DnsAdmins` group violates the Tier 0 boundary. Instead, delegate administrative permissions specifically to child DNS zones or individual record containers using granular DACLs rather than server-wide or container-wide write rights.
* **Workstation Dynamic DNS Registration**: Enforcing Secure Dynamic Updates while removing `Create all child objects` for `Authenticated Users` prevents standard user accounts from registering arbitrary records. Domain-joined computer accounts will continue to register and update their own computer name `A` and `AAAA` records dynamically via their machine credentials, or through DHCP servers configured with dedicated dynamic update credentials (`DnsUpdateProxy` hardening).
* **Vulnerability Mitigations**: Ensure Microsoft security patches CVE-2021-40469 and CVE-2025-58726 are applied on all Domain Controllers to enforce DLL path validation and patch Kerberos homoglyph normalization.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) & Active Directory Console Configuration

#### 1. Enforce DnsAdmins Group Hygiene via GPO Restricted Groups
1. Open **Group Policy Management** (`gpmc.msc`).
2. Edit the baseline GPO applied to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups`
4. Right-click **Restricted Groups** and select **Add Group...**.
5. Type `DnsAdmins` and click **OK**.
6. Under **Members of this group**, leave the member list **empty** (or populate it strictly with verified Tier 0 accounts such as `Domain Admins`).
7. Click **OK**.

#### 2. Prevent DNS DLL Hijacking via GPO Preferences Registry Policy
1. In the same GPO, navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
2. Right-click **Registry** -> **New** -> **Registry Item**.
3. Configure the following properties:
   * **Action**: `Delete`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\DNS\Parameters`
   * **Value Name**: `ServerLevelPluginDll`
4. Click **OK**.

#### 3. Enforce Secure Dynamic Updates on All AD-Integrated Zones
1. Open the **DNS Manager** console (`dnsmgmt.msc`) on a Domain Controller.
2. Expand the Domain Controller node -> **Forward Lookup Zones**.
3. Right-click each AD-integrated zone and select **Properties**.
4. On the **General** tab, set **Dynamic updates** to **Secure only**.
5. Repeat this configuration for all Forward and Reverse Lookup Zones.
6. Click **OK**.

#### 4. Restrict Arbitrary Record Creation & Ghost-SPN on ADIDNS Zones
1. In **DNS Manager**, right-click the domain DNS zone and select **Properties**.
2. Select the **Security** tab, then click **Advanced**.
3. Select the entry for **Authenticated Users** and click **Edit**.
4. Clear the **Create all child objects** (or **Create dnsNode objects**) permission to prevent standard domain users from creating arbitrary DNS records or Unicode homoglyphs.
5. Ensure machine accounts retain permissions to register their own hostname records, or utilize DHCP servers with dedicated service account credentials for dynamic updates.
6. Click **OK** to apply.

#### 5. Audit & Restrict Permissions on MicrosoftDNS Containers
1. Open **Active Directory Users and Computers** (`dsa.msc`) with **View** -> **Advanced Features** enabled.
2. Check permissions on `System\MicrosoftDNS`:
   * Right-click **MicrosoftDNS** -> **Properties** -> **Security**.
   * Verify that non-Tier 0 identities and `DnsAdmins` do not hold **Write all properties**, **Modify permissions**, or **Full Control**.
3. To inspect Application Partitions (`DomainDnsZones` and `ForestDnsZones`):
   * Open **ADSI Edit** (`adsiedit.msc`).
   * Connect to Naming Context: `DC=DomainDnsZones,DC=[Domain]` and navigate to `CN=MicrosoftDNS`.
   * Connect to Naming Context: `DC=ForestDnsZones,DC=[ForestRootDomain]` and navigate to `CN=MicrosoftDNS`.
   * Right-click **MicrosoftDNS** -> **Properties** -> **Security** -> **Advanced** and verify that only Tier 0 accounts possess write access.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script block to remove the `ServerLevelPluginDll` backdoor, enforce Secure Dynamic Updates on all AD-integrated zones, and audit `DnsAdmins` membership.

[Download Script: Harden-DnsServerConfiguration.ps1](implementation_scripts/Harden-DnsServerConfiguration.ps1)

```powershell
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
```

*To audit active DNS parameters, AD container permissions, dynamic updates, and homoglyph records:*

[Download Script: Get-DnsAuditStatus.ps1](audit_scripts/Get-DnsAuditStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R39 (DNS Administration and Tier 0 Boundary), Section 3.2.1, Section 3.6, Section 9
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 3.e (Page 23)
* **Microsoft Security Response Center**: CVE-2021-40469 Mitigation
* **Synacktiv Research / Microsoft**: CVE-2025-58726 (Ghost-SPN Kerberos & ADIDNS Reflection)
* **Other Reference**: CVE-2021-40469 (Windows DNS Server Remote Code Execution Vulnerability)
