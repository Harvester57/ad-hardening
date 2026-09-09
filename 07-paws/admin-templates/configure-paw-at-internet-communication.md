# [REQ-PAW-175] Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-186](../../08-endpoints/admin-templates/configure-end-at-internet-communication.md); for Domain Controllers, refer to [REQ-DC-027](../../02-domain-controllers/configure-telemetry-privacy.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn off downloading of print drivers over HTTP**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers`
    * Value Name: `DisableWebPnPDownload`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Disabled / Block HTTP print driver downloads)
  * **Turn off Internet download for Web publishing and online ordering wizards**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
    * Value Name: `NoWebServices`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Disabled / Block web wizard downloads)

---

## Rationale
Privileged Access Workstations (PAWs) reside in isolated administrative zones dedicated to the management of Active Directory Domain Controllers and enterprise tier-0 identity infrastructure. Automated internet communication channels, web wizard downloads, and dynamic HTTP driver retrieval represent intolerable attack surfaces on privileged hosts.

### 1. Eliminating Web Point and Print Exploitation Vectors
Dynamic printer driver acquisition over unencrypted HTTP (Web Point and Print) introduces severe privilege escalation vectors:
* **Privilege Escalation inside Print Spooler**: Print drivers execute with full administrative privileges within `spoolsv.exe` (`NT AUTHORITY\SYSTEM`). Vulnerabilities such as PrintNightmare (CVE-2021-1675 / CVE-2021-34527) demonstrated that malicious print drivers can achieve immediate, unconstrained code execution on the local system.
* **Adversary-in-the-Middle (AiTM) Poisoning**: If a PAW is connected to a local subnet or transit network where web printer discovery occurs, an adversary could forge HTTP driver download responses, injecting malicious binaries directly into the driver repository.
* Setting `DisableWebPnPDownload = 1` completely forbids the PAW from fetching print drivers over HTTP. PAWs should ideally have the Print Spooler service disabled entirely ([REQ-PAW-012](../disable-unnecessary-system-services.md)), but enforcing this policy provides essential defense-in-depth against accidental service activation.

### 2. Suppression of Unauthenticated Web Wizards and Outbound Telemetry
Windows Explorer includes legacy wizards for publishing media to the web or placing online print orders:
* **Outbound Traffic Egress**: These wizards attempt to connect to external Microsoft and third-party web endpoints, generating unauthenticated HTTP outbound requests that can leak workstation hostnames, network topologies, and metadata.
* **Data Exfiltration Vectors**: Legacy web wizards provide unmonitored file upload conduits that could be misused for unauthorized file egress.
* Setting `NoWebServices = 1` disables web wizard download functions, keeping Windows Explorer strictly offline and focused on local administrative tasks.

### 3. MITRE ATT&CK Mapping
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading / Driver Sideloading**: Sideloading rogue drivers through unauthenticated HTTP driver acquisition.
* **T1068 - Exploitation for Privilege Escalation**: Escalating to SYSTEM privileges via printer driver installation mechanisms.
* **T1048 - Exfiltration Over Alternative Protocol**: Unsanctioned data egress utilizing built-in web publishing wizards.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs are dedicated to directory administration and have zero legitimate requirement to connect to web-based printers or utilize consumer web publishing wizards.
* **Administrative Operations**: All administrative tooling is installed via approved enterprise software repositories or Microsoft-signed RSAT packages.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
  * **Turn off downloading of print drivers over HTTP**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
  * **Turn off Internet download for Web publishing and online ordering wizards**: Set to `Enabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtInternetCommunication.ps1](../implementation_scripts/Configure-PawAtInternetCommunication.ps1)

```powershell
#Configure-PawAtInternetCommunication.ps1
# Description: Configures Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs.

Write-Host "Configuring Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtInternetCommunicationStatus.ps1](../audit_scripts/Get-PawAtInternetCommunicationStatus.ps1)

```powershell
#Get-PawAtInternetCommunicationStatus.ps1
# Description: Audits Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs.

Write-Host "--- Auditing Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$ValueName = "DisableWebPnPDownload"
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

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName = "NoWebServices"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.30.2, Section 18.9.30.3; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.30.2, Section 18.9.30.3
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000280, WN10-CC-000285; Windows 11 STIG Rules WN11-CC-000280, WN11-CC-000285
* **ANSSI Active Directory Hardening Guide**: Section 3.2 (Restricting unnecessary internet-facing services and protocols)
* **Microsoft Privileged Access Workstation Guidance**: PAW Network and Service Exposure Rules
