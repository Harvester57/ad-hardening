# [REQ-NET-010] Harden WinRM Service and Restrict Remote RPC Clients

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **WinRM Client GPO**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client`
    * `Allow Basic authentication` -> Disabled
    * `Allow unencrypted traffic` -> Disabled
    * `Disallow Digest authentication` -> Enabled
  * **WinRM Service GPO**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service`
    * `Allow Basic authentication` -> Disabled
    * `Allow unencrypted traffic` -> Disabled
    * `Disallow WinRM from storing RunAs credentials` -> Enabled
  * **RPC Client Restraints GPO**: `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Restrict Unauthenticated RPC clients` -> Enabled (Set option to **Authenticated**)
  * **Registry Location (WinRM Client)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client`
    * `AllowBasic` = `0` (REG_DWORD)
    * `AllowUnencryptedTraffic` = `0` (REG_DWORD)
    * `AllowDigest` = `0` (REG_DWORD)
  * **Registry Location (WinRM Service)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`
    * `AllowBasic` = `0` (REG_DWORD)
    * `AllowUnencryptedTraffic` = `0` (REG_DWORD)
    * `DisableRunAs` = `1` (REG_DWORD)
  * **Registry Location (RPC Clients)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc` -> `RestrictRemoteClients` = `1` (REG_DWORD)

---

## Rationale
Windows Remote Management (WinRM) and Remote Procedure Call (RPC) are standard management interfaces in Windows environments. However, by default, these interfaces allow backward-compatible configurations that pose significant security risks.

Hardening these service channels blocks the following exploit vectors:
1. **Plaintext Credential Harvesting**: Allowing Basic authentication on WinRM clients and services allows transmission of administrative passwords in plaintext (or easily decodable formats) if secure channels are not established. Disabling Basic and Digest authentication forces the use of Kerberos or certificate-based authentication.
2. **Replay and Eavesdropping**: WinRM allows unencrypted traffic by default, which exposes administrative payloads and remote command execution streams to sniffing and hijacking. Forcing encryption protects the confidentiality and integrity of remote management sessions.
3. **RunAs Credential Exposure**: If WinRM is allowed to cache or store RunAs credentials for remote task execution, those credentials reside in the host's memory, where an administrative attacker can harvest them using memory extraction tools.
4. **Anonymous RPC Enumeration**: Restricting unauthenticated RPC clients prevents anonymous attackers from performing remote enumeration of active services, RPC interfaces, and registry endpoints, limiting remote reconnaissance capabilities.

---

## Legacy Impact & Compatibility
* **Administrative Tooling**: WinRM scripts, monitoring agents, or cross-domain management frameworks that rely on local accounts and Basic authentication to establish connections will fail. All administrative connections must be migrated to Kerberos or HTTPS with client certificate authentication.
* **RPC Queries**: Third-party scanners or legacy network devices that query RPC interfaces without authenticating will be blocked from accessing RPC data on hardened hosts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Configure WinRM Client Settings
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting all computers (e.g., `GPO_Computer_Hardening_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client`
4. Configure the settings:
   * **Policy**: `Allow Basic authentication` -> **Disabled**
   * **Policy**: `Allow unencrypted traffic` -> **Disabled**
   * **Policy**: `Disallow Digest authentication` -> **Enabled**

#### 2. Configure WinRM Service Settings
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service`
2. Configure the settings:
   * **Policy**: `Allow Basic authentication` -> **Disabled**
   * **Policy**: `Allow unencrypted traffic` -> **Disabled**
   * **Policy**: `Disallow WinRM from storing RunAs credentials` -> **Enabled**

#### 3. Configure RPC Client Restrictions
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call`
2. Double-click **Restrict Unauthenticated RPC clients**.
3. Set it to **Enabled**.
4. In the options dropdown, select **Authenticated** (corresponds to registry value `1`).
5. Click **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to enforce WinRM client/service and RPC restrictions in the registry.

[Download Script: Set-WinRMAndRpcHardening.ps1](implementation_scripts/Set-WinRMAndRpcHardening.ps1)

```powershell
# Set-WinRMAndRpcHardening.ps1
# Description: Hardens WinRM client/service parameters and restricts remote RPC clients.

Write-Host "Applying WinRM and RPC channel hardening settings..." -ForegroundColor Cyan

# 1. WinRM Client Hardening
$ClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if (-not (Test-Path $ClientPath)) {
    New-Item -Path $ClientPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientPath -Name "AllowBasic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ClientPath -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ClientPath -Name "AllowDigest" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] WinRM Client parameters hardened." -ForegroundColor Green

# 2. WinRM Service Hardening
$ServicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
if (-not (Test-Path $ServicePath)) {
    New-Item -Path $ServicePath -Force | Out-Null
}
Set-ItemProperty -Path $ServicePath -Name "AllowBasic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ServicePath -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $ServicePath -Name "DisableRunAs" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] WinRM Service parameters hardened." -ForegroundColor Green

# 3. RPC Client Restrictions
$RpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
if (-not (Test-Path $RpcPath)) {
    New-Item -Path $RpcPath -Force | Out-Null
}
Set-ItemProperty -Path $RpcPath -Name "RestrictRemoteClients" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Unauthenticated RPC client restrictions enforced (RestrictRemoteClients = 1)." -ForegroundColor Green
```

*To audit the WinRM client/service and RPC client settings status:*
[Download Script: Get-WinRMAndRpcHardeningStatus.ps1](audit_scripts/Get-WinRMAndRpcHardeningStatus.ps1)

```powershell
# Get-WinRMAndRpcHardeningStatus.ps1
# Description: Audits registry configuration of WinRM client/service options and RPC client restrictions.

Write-Host "--- Auditing WinRM and RPC Hardening Settings ---" -ForegroundColor Cyan

# 1. Audit WinRM Client
$ClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$ExpectedClient = @{
    "AllowBasic"              = 0
    "AllowUnencryptedTraffic" = 0
    "AllowDigest"             = 0
}
if (Test-Path $ClientPath) {
    $ClientReg = Get-ItemProperty -Path $ClientPath -ErrorAction SilentlyContinue
    foreach ($S in $ExpectedClient.Keys) {
        $Val = $ClientReg.$S
        $Expected = $ExpectedClient[$S]
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - WinRM Client $($S): $Val (Expected: $Expected)" -ForegroundColor $Color
    }
} else {
    Write-Host "    - WinRM Client Registry: NOT FOUND" -ForegroundColor Red
}

# 2. Audit WinRM Service
$ServicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$ExpectedService = @{
    "AllowBasic"              = 0
    "AllowUnencryptedTraffic" = 0
    "DisableRunAs"            = 1
}
if (Test-Path $ServicePath) {
    $ServiceReg = Get-ItemProperty -Path $ServicePath -ErrorAction SilentlyContinue
    foreach ($S in $ExpectedService.Keys) {
        $Val = $ServiceReg.$S
        $Expected = $ExpectedService[$S]
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - WinRM Service $($S): $Val (Expected: $Expected)" -ForegroundColor $Color
    }
} else {
    Write-Host "    - WinRM Service Registry: NOT FOUND" -ForegroundColor Red
}

# 3. Audit RPC Clients
$RpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$RpcVal = Get-ItemProperty -Path $RpcPath -Name "RestrictRemoteClients" -ErrorAction SilentlyContinue
$RpcSetting = if ($RpcVal) { $RpcVal.RestrictRemoteClients } else { 0 }
$RpcColor = if ($RpcSetting -eq 1) { "Green" } else { "Red" }
Write-Host "    - RPC RestrictRemoteClients: $RpcSetting (Expected: 1)" -ForegroundColor $RpcColor
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9 (Windows Remote Management), Section 18.1.2 (Remote Procedure Call)
* **ANSSI AD Hardening Guide**: Security guidelines regarding remote management and RPC access controls.
