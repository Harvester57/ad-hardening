# [REQ-PAW-197] Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-208](../../08-endpoints/admin-templates/configure-end-at-windows-sandbox-isolation.md)).*
* **Operating Systems**: Windows 10 Enterprise (1903+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Disable Clipboard Sharing with Windows Sandbox**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox\Allow clipboard sharing with Windows Sandbox` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox`
    * Value Name: `AllowClipboardRedirection`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Disable Networking in Windows Sandbox**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox\Allow networking in Windows Sandbox` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox`
    * Value Name: `AllowNetworking`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)

---

## Rationale
Privileged Access Workstations (PAWs) manage the enterprise's most sensitive Tier 0 identity boundaries. While Windows Sandbox allows isolated testing of administrative scripts or packages, running any virtualized container on a PAW without absolute host-isolation controls introduces severe risks to directory security.

### 1. Preventing Tier 0 Credential Exfiltration via Clipboard Redirection
PAW operators routinely handle high-entropy administrative secrets, including Kerberos tickets, directory recovery passwords, LSA secret tokens, and BitLocker recovery keys:
* When clipboard redirection is active, the containerized guest environment shares the Windows clipboard buffer with the host operating system.
* Malicious code or compromised testing utilities executing inside the sandbox can inspect the clipboard stream, capturing privileged credentials copied by the operator in other host management windows.
* In addition, guest-to-host clipboard injection allows container malware to replace clipboard text with weaponized administrative commands.
* Disabling `AllowClipboardRedirection` enforces total clipboard isolation, preventing cross-boundary credential leakage and injection attacks.

### 2. Guarding the Tier 0 Management Network from Container Traversal
By default, Windows Sandbox provisions a virtual network adapter that bridges into the host's network:
* On a PAW, the host's physical network connection has direct reachability to Tier 0 Domain Controllers, management hypervisors, and Hardware Security Modules (HSMs).
* Permitting network access within the sandbox gives containerized code an unobstructed network path to port-scan Domain Controllers, attempt Kerberos brute-forcing, or launch network exploits against directory infrastructure.
* Disabling `AllowNetworking` detaches the virtual network adapter, isolating the container in an offline air-gap state.

### 3. MITRE ATT&CK Mapping
* **T1115 - Clipboard Data**: Adversary interception of sensitive administrative credentials across virtualization boundaries.
* **T1071 - Application Layer Protocol**: Outbound communication to external adversary command and control nodes.
* **T1046 - Network Service Discovery**: Unauthorized network reconnaissance against Tier 0 directory services.
* **T1204.002 - User Execution: Malicious File**: Detonating untrusted scripts within privileged management environments.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None on standard administrative tasks. If administrators utilize Windows Sandbox to test PowerShell scripts or automation templates, they must stage all dependencies using offline folder mounts.
* **Network Testing**: Network-dependent scripts cannot be tested within the sandbox; such testing must be performed in dedicated, isolated staging laboratories rather than on production PAWs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox`
  * **Allow clipboard sharing with Windows Sandbox**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox`
  * **Allow networking in Windows Sandbox**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtWindowsSandboxIsolation.ps1](../implementation_scripts/Configure-PawAtWindowsSandboxIsolation.ps1)

```powershell
#Configure-PawAtWindowsSandboxIsolation.ps1
# Description: Configures Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs.

Write-Host "Configuring Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtWindowsSandboxIsolationStatus.ps1](../audit_scripts/Get-PawAtWindowsSandboxIsolationStatus.ps1)

```powershell
#Get-PawAtWindowsSandboxIsolationStatus.ps1
# Description: Audits Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs.

Write-Host "--- Auditing Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
$ValueName = "AllowClipboardRedirection"
$ExpectedValue = 0
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
$ValueName = "AllowNetworking"
$ExpectedValue = 0
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.106.1, Section 18.10.106.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.106.1, Section 18.10.106.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000360, Windows 11 STIG Rule WN11-CC-000360
* **Microsoft Privileged Access Workstation Guidance**: PAW Virtualization and Isolation Controls
