# Hardening Requirement: Harden Microsoft DNS AD Container Permissions

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory path: `CN=MicrosoftDNS,CN=System,DC=[Domain]` and Registry Path: `HKLM:\System\CurrentControlSet\Services\DNS\Parameters`

---

## Rationale
In Active Directory-integrated DNS zones, DNS server configurations and zone data are stored inside the directory. By default, members of the built-in `DnsAdmins` group have write permissions over the properties of the `CN=MicrosoftDNS,CN=System` container.

This default configuration presents a critical privilege escalation vector:
1. **DLL Hijacking via DNS Service**: An account with write permissions on the DNS container can specify a path to a malicious DLL in the `ServerLevelPluginDll` parameter. The DNS server service (which runs as `SYSTEM` on Domain Controllers) will load this DLL upon restart, executing arbitrary code with system privileges and leading to full Domain Controller takeover.
2. **Restricts DNS Management Boundary**: Restricting write access on the container properties and auditing the membership of the `DnsAdmins` group prevents lower-tier administrators (such as Tier 1 network administrators) from escalating their privileges to Tier 0.

---

## Legacy Impact & Compatibility
* **DNS Administrative Workloads**: Delegated network administrators who are not members of Tier 0 but manage DNS records may fail to perform some zone maintenance if they rely on membership in the default `DnsAdmins` group. They should instead be granted delegated rights over specific DNS zones rather than write access on the main DNS system container.
* **Vulnerability Mitigation**: Ensure that Microsoft security update CVE-2021-40469 is installed on all Domain Controllers to harden the DNS plugin loading behavior.

---

## Implementation Steps

### Option A: Active Directory Users and Computers (ADUC) Console Configuration

1. Open **Active Directory Users and Computers** (`dsa.msc`) on a Domain Controller.
2. Ensure **View** -> **Advanced Features** is checked.
3. Navigate to:
   `System\MicrosoftDNS`
4. Right-click **MicrosoftDNS** and select **Properties**.
5. Select the **Security** tab.
6. Select the **DnsAdmins** group or any non-Tier 0 administrative user/group.
7. Click **Advanced**.
8. Ensure they do not possess **Write all properties** or **Full Control** over the container.
9. Click **OK** to apply.
10. Open **Active Directory Users and Computers** and navigate to the `Builtin` or `Users` container.
11. Double-click the **DnsAdmins** group and ensure only Tier 0 accounts are members. Remove any non-Tier 0 identities.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script block to audit and remove the `ServerLevelPluginDll` registry backdoor on Domain Controllers, and verify DNSAdmins membership.

[Download Script: Harden-DnsServerConfiguration.ps1](implementation_scripts/Harden-DnsServerConfiguration.ps1)

```powershell
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
```

*To verify active DNS parameters and container permissions:*
[Download Script: Get-DnsAuditStatus.ps1](audit_scripts/Get-DnsAuditStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 3.e (Page 23)
* **ANSSI AD Hardening Guide**: Section 3.2.1, Section 3.6, Section 9
* **Microsoft Security Response Center**: CVE-2021-40469 Mitigation
* **Other Reference**: CVE-2021-40469 (Windows DNS Server Remote Code Execution Vulnerability)
