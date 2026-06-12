# Hardening Requirement: Disable Multicast Name Resolution

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Disable LLMNR**:
    * Path: `Computer Configuration\Policies\Administrative Templates\Network\DNS Client`
    * Policy: `Turn off multicast name resolution`
    * Setting: `Enabled`
    * Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` -> `EnableMulticast` = `0` (REG_DWORD)
  * **Disable mDNS**:
    * Path: `Computer Configuration\Preferences\Windows Settings\Registry`
    * Key Path: `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`
    * Value Name: `EnableMDNS`
    * Value Type: `REG_DWORD`
    * Value Data: `0`
  * **Disable NetBIOS (NBT-NS)**:
    * Path: `Computer Configuration\Preferences\Windows Settings\Registry`
    * Key Path: `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\<InterfaceKey>`
    * Value Name: `NetbiosOptions`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Disables NetBIOS over TCP/IP)

---

## Rationale
Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and multicast DNS (mDNS) are fallback name resolution protocols. When a Windows host is unable to resolve a name via standard DNS, it broadcasts the query to the local subnet using these protocols.

Adversaries on the same subnet can easily sniff these broadcast/multicast queries and respond with their own IP address (using tools such as Responder). When the requesting client attempts to authenticate to the fake host, its NTLM credentials (specifically NTLMv2 hashes) are captured by the attacker. These hashes can then be cracked offline or relayed to other hosts on the network (e.g., Active Directory Certificate Services or SMB servers) to achieve unauthorized administrative access. Disabling these legacy fallback protocols eliminates these name resolution spoofing attack vectors.

---

## Legacy Impact & Compatibility
* **DNS Dependency**: Once these protocols are disabled, hosts rely entirely on DNS. If DNS registration, DNS suffixes, or DNS servers are misconfigured, systems may fail to resolve names of adjacent local network resources.
* **Legacy System Impact**: Legacy applications or operating systems that do not use DNS for local hostname resolution will lose the ability to locate resources. A robust DNS infrastructure with dynamic registration enabled is a pre-requisite.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Configure Group Policy to disable LLMNR, and Group Policy Preferences to disable NetBIOS and mDNS:

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Network\DNS Client`
4. Set the following policy:
   * **Policy**: `Turn off multicast name resolution`
   * **Setting**: `Enabled`
5. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
6. Create a Registry Preference to disable mDNS (Right-click **Registry -> New -> Registry Item**):
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`
   * **Value name**: `EnableMDNS`
   * **Value type**: `REG_DWORD`
   * **Value data**: `0`
7. For NetBIOS, because adapter GUIDs vary, Group Policy Preferences can be configured with target registry keys, but NetBIOS disabling is often handled dynamically via DHCP scope options (Option 046 or by setting NetBIOS options via DHCP) or locally via scripting on server endpoints. Alternatively, create Registry Preferences for common interfaces or apply Option B locally.
8. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the settings locally.

[Download Script: Configure-DisableMulticastNameResolution.ps1](implementation_scripts/Configure-DisableMulticastNameResolution.ps1)

```powershell
# Configure-DisableMulticastNameResolution.ps1
# Description: Disables LLMNR, NetBIOS over TCP/IP, and mDNS on all interfaces.

Write-Host "Applying hardening requirement: Disable Multicast Name Resolution..." -ForegroundColor Cyan

# 1. Disable LLMNR
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "LLMNR disabled via registry policy." -ForegroundColor Green

# 2. Disable mDNS
$mdnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
if (-not (Test-Path $mdnsPath)) {
    New-Item -Path $mdnsPath -Force | Out-Null
}
Set-ItemProperty -Path $mdnsPath -Name "EnableMDNS" -Value 0 -Type DWord
Write-Host "mDNS disabled via registry." -ForegroundColor Green

# 3. Disable NetBIOS over TCP/IP on all Network Adapters
$interfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $interfacesPath) {
    $interfaces = Get-ChildItem -Path $interfacesPath
    foreach ($interface in $interfaces) {
        $intName = $interface.PSChildName
        $intPath = "$($interfacesPath)\$($intName)"
        Set-ItemProperty -Path $intPath -Name "NetbiosOptions" -Value 2 -Type DWord
        Write-Host "  NetBIOS disabled on interface: $($intName)" -ForegroundColor Gray
    }
    Write-Host "NetBIOS over TCP/IP disabled on all active interfaces." -ForegroundColor Green
} else {
    Write-Host "NetBIOS interfaces registry path not found." -ForegroundColor Yellow
}

Write-Host "Hardening applied successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-MulticastNameResolutionStatus.ps1](audit_scripts/Get-MulticastNameResolutionStatus.ps1)

```powershell
# Get-MulticastNameResolutionStatus.ps1
# Description: Audits LLMNR, NetBIOS, and mDNS registry settings.

Write-Host "--- Auditing Multicast Name Resolution ---" -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit LLMNR
$llmnrReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
if ($llmnrReg) {
    if ($llmnrReg.EnableMulticast -eq 1) {
        Write-Host "[!] VULNERABLE: LLMNR is explicitly enabled." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] LLMNR is disabled." -ForegroundColor Green
    }
} else {
    Write-Host "[!] VULNERABLE: LLMNR policy key 'EnableMulticast' does not exist (default is enabled)." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit mDNS
$mdnsReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
if ($mdnsReg) {
    if ($mdnsReg.EnableMDNS -ne 0) {
        Write-Host "[!] VULNERABLE: mDNS is enabled." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] mDNS is disabled." -ForegroundColor Green
    }
} else {
    # Default is enabled on Windows Server 2022 / Windows 11
    Write-Host "[!] VULNERABLE: mDNS key 'EnableMDNS' is missing (default is enabled)." -ForegroundColor Red
    $vulnerable = $true
}

# 3. Audit NetBIOS over TCP/IP
$interfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $interfacesPath) {
    $interfaces = Get-ChildItem -Path $interfacesPath
    $netbiosEnabledCount = 0
    foreach ($interface in $interfaces) {
        $intName = $interface.PSChildName
        $intPath = "$($interfacesPath)\$($intName)"
        $optVal = Get-ItemProperty -Path $intPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
        if ($optVal) {
            if ($optVal.NetbiosOptions -ne 2) {
                Write-Host "[!] VULNERABLE: NetBIOS is enabled/default on interface: $($intName) (NetbiosOptions = $($optVal.NetbiosOptions))" -ForegroundColor Red
                $netbiosEnabledCount = $netbiosEnabledCount + 1
            }
        } else {
            Write-Host "[!] VULNERABLE: NetbiosOptions value missing (default enabled) on interface: $($intName)" -ForegroundColor Red
            $netbiosEnabledCount = $netbiosEnabledCount + 1
        }
    }
    
    if ($netbiosEnabledCount -gt 0) {
        Write-Host "[!] VULNERABLE: NetBIOS over TCP/IP is active on $($netbiosEnabledCount) interface(s)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] NetBIOS over TCP/IP is disabled on all interfaces." -ForegroundColor Green
    }
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete and insecure protocols)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.8.19.1.1 (Ensure 'Turn off multicast name resolution' is set to 'Enabled')
* **Microsoft Security Guidance**: Recommendations for disabling NetBIOS on network adapters
