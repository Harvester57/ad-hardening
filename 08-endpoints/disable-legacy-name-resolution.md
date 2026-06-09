# Hardening Requirement: Disable Legacy Name Resolution

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Network\DNS Client\Turn off Multicast Name Resolution
  * HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_[Interface_GUID]\NetbiosOptions

---

## Rationale
Legacy name resolution protocols like Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and multicast DNS (mDNS) are fallback mechanisms used when local DNS queries fail. 

When a system attempts to resolve a host name that is not present in local DNS, it broadcasts LLMNR or NetBIOS requests to the local network. Attackers on the same network subnet can spoof these resolution requests (using tools like Responder) and coerce the requesting workstation into transmitting authentication credentials (typically NTLMv2 session hashes). The attacker can then crack these hashes offline or relay them to other domain services to gain unauthorized access. Disabling these protocols prevents this broadcast-based credential harvesting.

---

## Legacy Impact & Compatibility
* **DNS Dependency**: Local network hostnames must be correctly defined in the Active Directory DNS zone. Systems will no longer fall back to broadcasting when a host cannot be resolved.
* **P2P Printing and File Sharing**: Local workgroups or ad-hoc networking functions (like peer-to-peer file sharing or network discovery of home/workgroup-shared printers) that rely on NetBIOS naming will cease to function.
* **DHCP Configuration**: NetBIOS can also be disabled domain-wide by configuring DHCP option 043 (Vendor Specific Information) on the local DHCP server, but registry/GPO configuration is required to guarantee local adapter enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Turn Off LLMNR
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Network\DNS Client`
4. Configure the setting:
   * **Policy**: `Turn off Multicast Name Resolution`
   * **Setting**: `Enabled`

#### 2. Disable NetBIOS (via DHCP Server or Registry GPO Preferences)
Since NetBIOS cannot be directly disabled via standard GPO administrative templates, configure it on your DHCP server:
1. Open the **DHCP Management Console** (`dhcpmgmt.msc`).
2. Select your scope options.
3. Add **Option 043 (Vendor Specific Info)** and set the NetBIOS over TCP/IP value to `0x2` (Disable NetBIOS over TCP/IP).

Alternatively, deploy the Registry setting via GPO Preferences to target interfaces:
1. Under your GPO, navigate to `Computer Configuration\Preferences\Windows Settings\Registry`.
2. Deploy the key to set `NetbiosOptions` to `2` under the interface paths.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable LLMNR and disable NetBIOS on all active network adapters.

```powershell
# Disable-LegacyNameResolution.ps1
# Disables LLMNR in registry and NetBIOS over TCP/IP on all network adapters.

Write-Host "--- Disabling LLMNR & NetBIOS ---" -ForegroundColor Cyan

# 1. Disable LLMNR in Registry
$DNSClientPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $DNSClientPath)) {
    New-Item -Path $DNSClientPath -Force | Out-Null
}
Set-ItemProperty -Path $DNSClientPath -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "[+] LLMNR (Multicast Name Resolution) disabled." -ForegroundColor Green

# 2. Disable NetBIOS over TCP/IP on all active adapters
Write-Host "[+] Disabling NetBIOS on all active adapters..." -ForegroundColor Gray
$Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($Adapter in $Adapters) {
    # 2 = Disable NetBIOS over TCP/IP
    Invoke-CimMethod -InputObject $Adapter -MethodName SetTCPIPNetBIOS -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
}
Write-Host "    NetBIOS disabled on all network interfaces." -ForegroundColor Green
```

*To audit the name resolution status:*
```powershell
# Test-LegacyNameResolution.ps1
# Audits LLMNR registry values and NetBIOS adapter parameters.

Write-Host "--- Auditing Name Resolution Settings ---" -ForegroundColor Cyan

# 1. Audit LLMNR
$DNSPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
$LlmnrVal = Get-ItemProperty -Path $DNSPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
$LlmnrSetting = if ($LlmnrVal) { $LlmnrVal.EnableMulticast } else { 1 }
$LlmnrColor = if ($LlmnrSetting -eq 0) { "Green" } else { "Red" }
Write-Host "    - LLMNR Enabled Value: $LlmnrSetting (Required = 0 to Disable)" -ForegroundColor $LlmnrColor

# 2. Audit NetBIOS status on active interfaces
$Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($Adapter in $Adapters) {
    $RegAdapterPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($Adapter.SettingID)"
    $NetBiosOpt = Get-ItemProperty -Path $RegAdapterPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
    $NetBiosOptVal = if ($NetBiosOpt) { $NetBiosOpt.NetbiosOptions } else { 0 }
    $NetBiosColor = if ($NetBiosOptVal -eq 2) { "Green" } else { "Red" }
    Write-Host "    - Interface: $($Adapter.Description) | NetbiosOptions: $NetBiosOptVal (Required = 2 to Disable)" -ForegroundColor $NetBiosColor
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 9.1 (Disable LLMNR)
* **ANSSI AD Hardening Guide**: Recommendation R19 (LDAP and name resolution security recommendations)
