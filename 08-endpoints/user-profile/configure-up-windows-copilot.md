# [REQ-END-128] User Profile: Windows Copilot Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-117](../../07-paws/user-profile/configure-up-windows-copilot.md)).*
* **Operating Systems**: Windows 11 Enterprise/Pro (all supported builds), Windows 10 Enterprise (where Copilot components are backported).

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn Off Windows Copilot (User Configuration)**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Windows Copilot\Turn off Windows Copilot` -> **Enabled**
    * Registry Path: `HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot`
    * Value Name: `TurnOffWindowsCopilot`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Completely disable Windows Copilot)
  * **Turn Off Windows Copilot (Computer Configuration)**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Copilot\Turn off Windows Copilot` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot`
    * Value Name: `TurnOffWindowsCopilot`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Completely disable Windows Copilot machine-wide)

---

## Rationale
Windows Copilot is an artificial intelligence assistant deeply integrated into the Windows 11 desktop shell, Edge browser runtime, and search experience. Copilot utilizes cloud-hosted large language models (LLMs) to synthesize user requests, summarize screen contents, and assist with desktop workflows. In an enterprise environment, unconstrained deployment of generative AI interfaces introduces critical data loss prevention (DLP), regulatory compliance, and credential exposure hazards.

### 1. Copilot Architecture & Contextual Data Processing
Windows Copilot operates by bridging local user session data with cloud-based AI endpoints:
* **Active Window and Screen Context**: Copilot possesses capabilities to read the active application window, summarize active browser tabs, and capture desktop screenshots for multimodal prompt processing.
* **Clipboard Interaction**: Users frequently copy sensitive information—including customer personal data, internal IP ranges, proprietary source code, database queries, and credentials—into the Windows clipboard buffer (`clip.exe`). Copilot prompts may ingest or process clipboard context to provide contextual suggestions.
* **External Cloud Transmission**: Prompts and context processed by Copilot are transmitted to cloud infrastructure over HTTPS. In unhardened environments, sensitive business data, intellectual property, or personally identifiable information (PII) may be sent to cloud endpoints outside corporate data residency and sovereignty boundaries.

### 2. Threat Vectors & Enterprise Exposure
* **Unauthorized Data Exfiltration**: Malicious or unauthorized prompts can coerce the assistant into summarizing and transmitting confidential local file contents to external cloud services.
* **Regulatory Non-Compliance**: Transmitting unvetted business communications or personal data violates strict regulatory frameworks, such as the European General Data Protection Regulation (GDPR), HIPAA, or defense procurement standards.
* **Credential Exposure**: Accidental inclusion of API keys, passwords, or connection strings in Copilot prompt fields creates permanent records in cloud prompt histories.
* Setting `TurnOffWindowsCopilot = 1` across both user and machine policies completely removes the Copilot shell sidebar, suppresses the `Win + C` keyboard shortcut, and terminates background AI communication shims.

### 3. MITRE ATT&CK Mapping
* **T1005 - Data from Local System**: Extracting confidential information from local desktop files and applications.
* **T1048 - Exfiltration Over Alternative Protocol: Exfiltration to Cloud Storage**: Transmitting local enterprise context to cloud AI endpoints.
* **T1115 - Clipboard Data**: Ingesting sensitive authentication or operational data from the system clipboard.

---

## Legacy Impact & Compatibility
* **Standard User Operations**: Disabling Copilot has zero impact on core operating system stability, standard search functionality, or business productivity applications.
* **Taskbar Cleanliness**: Removes the Copilot icon from the Windows taskbar and prevents accidental activation via keyboard shortcuts.
* **Enterprise AI Deployments**: Organizations with sanctioned, tenant-isolated enterprise AI deployments (e.g., Microsoft 365 Copilot with commercial data protection within Microsoft Edge) can govern web-based AI usage via dedicated browser policies while keeping shell-integrated Copilot disabled.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Windows Copilot`
  * **Turn off Windows Copilot**: Set to **Enabled**
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Copilot`
  * **Turn off Windows Copilot**: Set to **Enabled**

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Windows Copilot:

[Download Script: Configure-Upwindowscopilot.ps1](../implementation_scripts/Configure-Upwindowscopilot.ps1)

```powershell
# Configure-Upwindowscopilot.ps1
Write-Host "Applying User Profile restriction: windows-copilot..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" "1" "DWord"

# Apply to Default User profile for new sessions
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultHivePath) {
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "TurnOffWindowsCopilot" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

```

*To audit the hardening status:*

[Download Script: Get-UpwindowscopilotStatus.ps1](../audit_scripts/Get-UpwindowscopilotStatus.ps1)

```powershell
# Get-UpwindowscopilotStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" "1"

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x (Windows Copilot)
* **DISA STIG**: Windows 11 STIG Rule WN11-CC-000145
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing user profiles and disabling generative AI desktop integration)
* **Microsoft Security Guidance**: Managing Windows Copilot Enterprise Controls and Data Protection
