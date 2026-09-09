# [REQ-END-201] Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-190](../../07-paws/admin-templates/configure-paw-at-file-explorer-motw.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Windows Attachment Manager and File Explorer utilize the Mark of the Web (MotW) as a core security boundary. MotW is implemented as an NTFS Alternate Data Stream (ADS) named `Zone.Identifier` appended to files downloaded from the internet or untrusted network zones. Maintaining strict MotW integrity and enforcing shell protocol protected mode are essential defenses against initial-access malware campaigns.

### 1. Mark of the Web (Zone.Identifier) Defense Mechanisms
The `Zone.Identifier` stream identifies the origin security zone of downloaded content (typically `ZoneId=3` for the Internet zone):
* **Triggering Critical Security Defenses**: The presence of the MotW tag automatically activates multiple defense-in-depth controls:
  * **Microsoft Defender SmartScreen**: Initiates cloud-based reputation checks and blocks unknown or malicious executables.
  * **Microsoft 365 / Office Protected View**: Opens downloaded documents in read-only sandbox mode, preventing automated VBA macro execution and Dynamic Data Exchange (DDE) exploits.
  * **Windows PowerShell Execution Policies**: Blocks execution of downloaded `.ps1` scripts unless explicitly unblocked.
* **The MotW Stripping Threat Vector**: Threat actors routinely attempt to bypass MotW by packaging malware inside containers (ISO, VHD, ZIP) or coercing users to copy files across network shares (SMB or WebDAV). If `DisableMotWOnInsecurePathCopy` is misconfigured or set to `1`, File Explorer removes the `Zone.Identifier` stream during file copy operations, effectively laundering the untrusted file into a trusted local asset.
* Setting `DisableMotWOnInsecurePathCopy = 0` (GPO: **Disabled**) guarantees that File Explorer preserves and applies MotW tags even when files are copied from insecure network paths.

### 2. Shell Protocol Protected Mode Enforcement
The Windows shell supports URI protocols (such as `file:`, `shell:`, `mailto:`, and third-party application protocols) executed via `ShellExecute`:
* **Legacy Shell Protocol Risks**: In obsolete Windows releases, shell protocols executed arbitrary command parameters and external URLs without parameter sanitization or security prompt verification. Adversaries exploit legacy shell protocol behaviors (as demonstrated in CVE-2023-36025 and CVE-2024-21412) to bypass SmartScreen and trigger indirect code execution.
* Setting `PreXPSP2ShellProtocolBehavior = 0` (GPO: **Disabled**) forces File Explorer to operate in modern Protected Mode. The shell sanitizes protocol parameters, restricts nested command invocation, and prompts users before launching external protocol handlers.

### 3. MITRE ATT&CK Mapping
* **T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass**: Circumventing SmartScreen, Application Control, and Office Protected View by stripping MotW streams.
* **T1204.002 - User Execution: Malicious File**: Opening untrusted documents or executable packages lacking security origin tags.
* **T1218 - System Binary Proxy Execution**: Abusing shell protocol handlers to launch payloads via trusted Windows binaries.

---

## Legacy Impact & Compatibility
* **User Experience**: Users executing files downloaded from external networks will continue to receive standard Windows security confirmation prompts and SmartScreen validation dialogs.
* **Internal Network Shares**: Enterprise files transferred between fully trusted internal intranet file servers (configured under the Local Intranet zone via GPO) will not receive intrusive prompts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer`
  * **Do not apply the Mark of the Web tag to files copied from insecure sources**: Set to `Disabled` (Ensures MotW is applied)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer`
  * **Turn off shell protocol protected mode**: Set to `Disabled` (Ensures Protected Mode is enforced)

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtFileExplorerMotw.ps1](../implementation_scripts/Configure-EndAtFileExplorerMotw.ps1)

```powershell
#Configure-EndAtFileExplorerMotw.ps1
# Description: Configures Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security.

Write-Host "Configuring Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableMotWOnInsecurePathCopy" -Value 0 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtFileExplorerMotwStatus.ps1](../audit_scripts/Get-EndAtFileExplorerMotwStatus.ps1)

```powershell
#Get-EndAtFileExplorerMotwStatus.ps1
# Description: Audits Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security.

Write-Host "--- Auditing Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security ---" -ForegroundColor Cyan
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
* **Microsoft Security Guidance**: Mark of the Web Architecture and Attachment Manager Defense Specifications
* **ANSSI Active Directory Hardening Guide**: Section 3.3 (Protection against untrusted file execution and web downloads)
