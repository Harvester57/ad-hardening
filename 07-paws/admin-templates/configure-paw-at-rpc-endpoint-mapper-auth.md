# [REQ-PAW-180] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-191](../../08-endpoints/admin-templates/configure-end-at-rpc-endpoint-mapper-auth.md); for Domain Controllers, refer to [REQ-DC-018](../../02-domain-controllers/harden-network-parameters.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) execute high-privilege Remote Procedure Call (RPC) routines when administering Domain Controllers, certificate authorities, and directory services. Hardening the RPC resolution mechanism is essential to protect administrative credentials and prevent malicious traffic redirection.

### 1. Guarding Privileged Management RPC Channels
Tier 0 administrative tools (such as Active Directory Users and Computers, Group Policy Management, and remote PowerShell remoting over WinRM/DCOM) interact with Domain Controllers across several RPC protocols:
* When a PAW initiates an RPC binding to a Domain Controller interface (such as MS-DRSR, MS-SAMR, or MS-LSAD), it queries the target's RPC Endpoint Mapper (`epmapper`) on TCP port 135 to discover the dynamic TCP port assigned to that interface.
* In unhardened environments, this initial query is unauthenticated. An attacker with network access to the management VLAN could spoof the response packet, redirecting the PAW's subsequent RPC call to a rogue endpoint.
* If redirected, the PAW could inadvertently transmit Tier 0 administrative Kerberos service tickets or NTLM authentications to the rogue host, exposing administrative credentials to relaying or offline cracking.

### 2. Enforcing Cryptographic Resolution Verification
Setting `EnableAuthEpResolution = 1` forces the PAW's RPC runtime (`rpcrt4.dll`) to mutually authenticate with the target endpoint mapper before requesting interface bindings:
* The lookup requires Kerberos mutual authentication against the target Domain Controller's computer account SPN.
* Integrity signing is enforced on the returned port mapping, guaranteeing that network adversaries cannot alter the dynamic port assignment.
* The PAW unconditionally drops connections to unauthenticated endpoint mappers, eliminating exposure to AiTM redirection.

### 3. MITRE ATT&CK Mapping
* **T1046 - Network Service Discovery**: Anonymous enumeration of RPC interfaces on management workstations.
* **T1557 - Adversary-in-the-Middle**: Spoofing RPC endpoint mappings to intercept administrative sessions.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Abuse of RPC services for lateral movement.

---

## Legacy Impact & Compatibility
* **Tier 0 Operational Compatibility**: All supported Windows Server releases (2016 through 2025) running as Domain Controllers natively support authenticated RPC endpoint resolution. PAW administrative tools function seamlessly using Kerberos authentication.
* **Workgroup and Non-Domain Systems**: Because PAWs are strictly restricted to managing Tier 0 Active Directory domain assets and never connect to untrusted non-domain nodes, no compatibility issues arise.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call`
  * **Enable RPC Endpoint Mapper Client Authentication**: Set to `Enabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtRpcEndpointMapperAuth.ps1](../implementation_scripts/Configure-PawAtRpcEndpointMapperAuth.ps1)

```powershell
#Configure-PawAtRpcEndpointMapperAuth.ps1
# Description: Configures Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs.

Write-Host "Configuring Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtRpcEndpointMapperAuthStatus.ps1](../audit_scripts/Get-PawAtRpcEndpointMapperAuthStatus.ps1)

```powershell
#Get-PawAtRpcEndpointMapperAuthStatus.ps1
# Description: Audits Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs.

Write-Host "--- Auditing Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.36.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.36.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000300, Windows 11 STIG Rule WN11-CC-000300
* **ANSSI Active Directory Hardening Guide**: Recommendation R34 (Securing RPC endpoint mapping and remote procedure calls)
* **Microsoft Privileged Access Workstation Guidance**: PAW Component and Management Network Protection Rules
