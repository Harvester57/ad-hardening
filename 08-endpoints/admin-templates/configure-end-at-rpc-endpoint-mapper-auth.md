# [REQ-END-191] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-180](../../07-paws/admin-templates/configure-paw-at-rpc-endpoint-mapper-auth.md); for Domain Controllers, refer to [REQ-DC-018](../../02-domain-controllers/harden-network-parameters.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Enable RPC Endpoint Mapper Client Authentication**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Enable RPC Endpoint Mapper Client Authentication` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc`
    * Value Name: `EnableAuthEpResolution`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Authenticate to Endpoint Mapper)

---

## Rationale
The Remote Procedure Call (RPC) subsystem is fundamental to Windows inter-process communication and remote management. The RPC Endpoint Mapper service (`epmapper`, listening on TCP port 135) maintains a dynamic database of RPC servers and maps interface UUIDs to dynamic high-range TCP listening ports (ports 49152–65535).

### 1. Threat Vectors and Unauthenticated RPC Reconnaissance
In default legacy Windows configurations, queries to the RPC Endpoint Mapper occur without authentication:
* **Anonymous Interface Enumeration**: An unauthenticated attacker on the local network can query TCP port 135 using tools such as `rpcdump.py`, `impacket`, or `rpcclient` to enumerate every registered RPC interface, exposed service handler, and dynamic port on the system. This reveals software versions, active administrative services (such as Task Scheduler, Event Log, or Volume Shadow Copy), and potential exploit targets.
* **Adversary-in-the-Middle (AiTM) Port Redirection**: When an RPC client queries an unauthenticated Endpoint Mapper across an untrusted network, an adversary positioned on the network path can forge the response packet. The attacker can return an arbitrary IP address or listening port, steering the client's subsequent high-privilege RPC call (carrying Kerberos or NTLM authentication credentials) to an attacker-controlled listener.
* **Coercion Vector Prerequisite**: Authentication coercion attacks (such as PetitPotam / MS-EFSR, DFSCoerce, or ShadowCoerce) rely on unauthenticated or weakly validated RPC interface binding before issuing unauthenticated method invocations that trigger outbound authentication handshakes.

### 2. Cryptographic and Authentication Enforcement
Enabling `EnableAuthEpResolution = 1` enforces strict client-side verification:
* The Windows RPC client runtime (`rpcrt4.dll`) is mandated to authenticate against the RPC Endpoint Mapper before resolving dynamic server endpoints.
* Mutual authentication is negotiated using Kerberos or NTLM, and cryptographic integrity signing is applied to the resolution response.
* If the target endpoint mapper cannot be authenticated or fails validation, the client aborts the connection attempt rather than falling back to unauthenticated resolution, neutralizing AiTM tampering and dynamic port redirection.

### 3. MITRE ATT&CK Mapping
* **T1046 - Network Service Discovery**: Anonymous enumeration of RPC interfaces and active services via TCP 135.
* **T1557 - Adversary-in-the-Middle**: Tampering with unauthenticated RPC endpoint mapper responses to hijack subsequent service sessions.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Lateral movement through RPC-based management interfaces.

---

## Legacy Impact & Compatibility
* **Active Directory Domain Compatibility**: All supported Windows operating systems (Windows 10, Windows 11, Windows Server 2016 through 2025) fully support authenticated RPC endpoint resolution. Active Directory domain-joined machines use Kerberos tickets to seamlessly authenticate against the Endpoint Mapper of other domain members.
* **Third-Party UNIX/Linux DCE-RPC Clients**: Non-Windows legacy clients or custom appliances utilizing bare DCE/RPC implementations that lack SPNEGO/Kerberos authentication extensions may fail to resolve dynamic RPC endpoints on hardened systems. Such legacy applications must be modernized to support standard GSS-API / Kerberos authentication.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call`
  * **Enable RPC Endpoint Mapper Client Authentication**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtRpcEndpointMapperAuth.ps1](../implementation_scripts/Configure-EndAtRpcEndpointMapperAuth.ps1)

```powershell
#Configure-EndAtRpcEndpointMapperAuth.ps1
# Description: Configures Administrative Templates: Enable RPC Endpoint Mapper Client Authentication.

Write-Host "Configuring Administrative Templates: Enable RPC Endpoint Mapper Client Authentication..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtRpcEndpointMapperAuthStatus.ps1](../audit_scripts/Get-EndAtRpcEndpointMapperAuthStatus.ps1)

```powershell
#Get-EndAtRpcEndpointMapperAuthStatus.ps1
# Description: Audits Administrative Templates: Enable RPC Endpoint Mapper Client Authentication.

Write-Host "--- Auditing Administrative Templates: Enable RPC Endpoint Mapper Client Authentication ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$ValueName = "EnableAuthEpResolution"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.36.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.36.1; CIS Windows Server Benchmark: Section 18.9.36.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000300, Windows 11 STIG Rule WN11-CC-000300
* **ANSSI Active Directory Hardening Guide**: Recommendation R34 (Securing RPC endpoint mapping and remote procedure calls)
* **Microsoft Security Baseline**: Recommended RPC Component Hardening Guidelines
