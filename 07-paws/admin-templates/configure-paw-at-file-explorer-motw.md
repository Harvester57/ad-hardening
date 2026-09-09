# [REQ-PAW-190] Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-201](../../08-endpoints/admin-templates/configure-end-at-file-explorer-motw.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Do not apply the Mark of the Web tag to files copied from insecure sources**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Do not apply the Mark of the Web tag to files copied from insecure sources` -> **Disabled** (Enforces MotW tagging)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer`
    * Value Name: `DisableMotWOnInsecurePathCopy`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / MotW preserved)
  * **Turn off shell protocol protected mode**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off shell protocol protected mode` -> **Disabled** (Enforces shell protocol protected mode)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
    * Value Name: `PreXPSP2ShellProtocolBehavior`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Protected mode enforced)

---

## Rationale
Privileged Access Workstations (PAWs) represent Tier 0 administrative boundaries. Protecting these high-value machines against unauthorized code execution requires enforcing all layers of Windows execution policy and download origin tracking.

### 1. Preserving Origin Metadata for Administrative Assets
When administrative scripts, tools, or update archives are staged onto a PAW across network paths:
* The Mark of the Web (`Zone.Identifier` alternate data stream) serves as the primary metadata indicator alerting the operating system that a file originated from outside the trusted local security zone.
* The presence of this tag triggers Windows Defender SmartScreen, PowerShell Execution Policy restrictions (`AllSigned` or `RemoteSigned`), and attachment inspection handlers.
* If MotW tags are stripped during file copy operations across network shares, untrusted scripts could execute with unvetted administrative authority.
* Disabling `DisableMotWOnInsecurePathCopy` ensures that the `Zone.Identifier` ADS is strictly preserved during file transfers, preventing the accidental laundering of untrusted binaries into trusted local assets.

### 2. Guarding Against Shell Protocol Parameter Injection
Privileged administrative shells must never execute unsanitized protocol parameters:
* Disabling Protected Mode (`PreXPSP2ShellProtocolBehavior = 1`) exposes the operating system to legacy shell vulnerabilities where malicious URLs or shortcut files (`.lnk`, `.url`) invoke external binaries with arbitrary command arguments.
* Enforcing `PreXPSP2ShellProtocolBehavior = 0` guarantees that File Explorer validates and sanitizes all shell protocol parameters, prompting the operator and preventing argument injection exploits.

### 3. MITRE ATT&CK Mapping
* **T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass**: Circumventing execution controls by stripping MotW metadata.
* **T1204.002 - User Execution: Malicious File**: Inadvertent execution of untrusted scripts or tools on a PAW.
* **T1218 - System Binary Proxy Execution**: Proxying execution via vulnerable shell protocol handlers.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None on legitimate administration. Administrative scripts and binaries officially approved for Tier 0 deployment are digitally signed by an internal enterprise code-signing certificate and trusted by AppLocker / WDAC policies.
* **Administrative Tooling**: Unsigned or untrusted third-party utilities copied onto a PAW will trigger standard security warnings, requiring administrators to review and verify the tool before execution.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer`
  * **Do not apply the Mark of the Web tag to files copied from insecure sources**: Set to `Disabled` (Ensures MotW is applied)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer`
  * **Turn off shell protocol protected mode**: Set to `Disabled` (Ensures Protected Mode is enforced)

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtFileExplorerMotw.ps1](../implementation_scripts/Configure-PawAtFileExplorerMotw.ps1)

```powershell
#Configure-PawAtFileExplorerMotw.ps1
# Description: Configures Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs.

Write-Host "Configuring Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableMotWOnInsecurePathCopy" -Value 0 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtFileExplorerMotwStatus.ps1](../audit_scripts/Get-PawAtFileExplorerMotwStatus.ps1)

```powershell
#Get-PawAtFileExplorerMotwStatus.ps1
# Description: Audits Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs.

Write-Host "--- Auditing Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$ValueName = "DisableMotWOnInsecurePathCopy"
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

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName = "PreXPSP2ShellProtocolBehavior"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.43.3, Section 18.10.43.14; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.43.3, Section 18.10.43.14
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000370, Windows 11 STIG Rule WN11-CC-000370
* **Microsoft Privileged Access Workstation Guidance**: Tier 0 File System Integrity and Host Execution Policy
