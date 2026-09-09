# [REQ-END-208] Administrative Templates: Windows Sandbox Clipboard and Network Isolation

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-197](../../07-paws/admin-templates/configure-paw-at-windows-sandbox-isolation.md)).*
* **Operating Systems**: Windows 10 (1903 and above) Enterprise/Professional, Windows 11 Enterprise/Pro.

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
Windows Sandbox provides a disposable, containerized desktop environment based on Hyper-V virtualization technology. While designed for the isolated execution of untrusted applications and triage of suspicious documents, default sandbox configurations permit bidirectional clipboard synchronization and shared network access, introducing significant breach risks.

### 1. Clipboard Interception and Cross-Boundary Tampering
By default, Windows Sandbox links the host and guest clipboards through an internal Remote Desktop Protocol (RDP) virtual channel:
* **Clipboard Data Harvesting**: Untrusted binaries detonated inside the sandbox can monitor clipboard activity. If an analyst or user copies passwords, Kerberos credentials, API secrets, or sensitive corporate intellectual property on the host operating system, malware in the container can intercept the clipboard buffer via standard Windows API calls.
* **Clipboard Injection and Host Execution**: Sophisticated malware within the sandbox can overwrite the host clipboard with malicious payloads (such as obfuscated PowerShell commands). If the user subsequently pastes into a host administrative console (PowerShell, CMD, or Run prompt), the injected payload executes directly in the host security context, breaking the container boundary.
* Setting `AllowClipboardRedirection = 0` severs the clipboard virtual channel, ensuring zero bidirectional data transfer.

### 2. Eliminating Command-and-Control and Lateral Network Movement
Default sandbox configurations create an internal virtual network switch (NAT) that bridges the container to the host's physical network adapters:
* **Command-and-Control (C2) Communication**: Malicious software executed inside the sandbox can establish outbound connections to external adversary infrastructure, exfiltrating host environment data, receiving secondary-stage payloads, or participating in DDoS attacks.
* **Internal Network Scanning and Lateral Movement**: The sandbox guest shares layer-3 reachability with the local enterprise network. Malicious code running inside the sandbox can scan corporate subnets, enumerate Active Directory Domain Controllers, exploit unpatched internal services, or launch pass-the-hash attacks against adjacent member servers.
* Setting `AllowNetworking = 0` instructs the Hyper-V container manager to instantiate the sandbox without a virtual network adapter, isolating the environment in a strict offline sandbox.

### 3. MITRE ATT&CK Mapping
* **T1115 - Clipboard Data**: Adversary monitoring and extraction of sensitive clipboard data across virtualization boundaries.
* **T1071 - Application Layer Protocol**: Outbound communication to external adversary command and control nodes.
* **T1046 - Network Service Discovery**: Scanning internal corporate networks and directory services from within the container.
* **T1204.002 - User Execution: Malicious File**: Detonating untrusted binaries within isolated testing environments.

---

## Legacy Impact & Compatibility
* **Malware Analysis and Triage**: Analysts can safely detonate and inspect suspicious files, scripts, and applications without risk of network egress or host credential theft.
* **Network-Dependent Software**: Packaged applications requiring active internet or intranet network connectivity will fail to communicate. Files and dependencies required for offline analysis must be mapped into the container via custom XML `.wsb` sandbox configuration files with read-only host folder mounts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox`
  * **Allow clipboard sharing with Windows Sandbox**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox`
  * **Allow networking in Windows Sandbox**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtWindowsSandboxIsolation.ps1](../implementation_scripts/Configure-EndAtWindowsSandboxIsolation.ps1)

```powershell
#Configure-EndAtWindowsSandboxIsolation.ps1
# Description: Configures Administrative Templates: Windows Sandbox Clipboard and Network Isolation.

Write-Host "Configuring Administrative Templates: Windows Sandbox Clipboard and Network Isolation..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Sandbox Clipboard and Network Isolation applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtWindowsSandboxIsolationStatus.ps1](../audit_scripts/Get-EndAtWindowsSandboxIsolationStatus.ps1)

```powershell
#Get-EndAtWindowsSandboxIsolationStatus.ps1
# Description: Audits Administrative Templates: Windows Sandbox Clipboard and Network Isolation.

Write-Host "--- Auditing Administrative Templates: Windows Sandbox Clipboard and Network Isolation ---" -ForegroundColor Cyan
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
* **Microsoft Security Baseline**: Windows Sandbox Component Security Recommendations
* **ANSSI Active Directory Hardening Guide**: Section 3.3 (Isolation of untrusted code execution environments)
