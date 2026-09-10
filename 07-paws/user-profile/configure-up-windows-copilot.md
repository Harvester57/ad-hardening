# [REQ-PAW-117] User Profile: Windows Copilot Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-128](../../08-endpoints/user-profile/configure-up-windows-copilot.md)).*
* **Operating Systems**: Windows 11 Enterprise, Windows 10 Enterprise (version 1809 and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn Off Windows Copilot (User Configuration)**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Windows Copilot\Turn off Windows Copilot` -> **Enabled**
    * Registry Path: `HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot`
    * Value Name: `TurnOffWindowsCopilot`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Strictly prohibit Windows Copilot)
  * **Turn Off Windows Copilot (Computer Configuration)**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Copilot\Turn off Windows Copilot` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot`
    * Value Name: `TurnOffWindowsCopilot`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Strictly prohibit Windows Copilot machine-wide)

---

## Rationale
Privileged Access Workstations (PAWs) handle the most sensitive infrastructure secrets in the Active Directory enterprise: Domain Controller recovery keys, Kerberos KRBTGT hashes, schema definitions, and cloud tenant administrative tokens. Generative AI assistants integrated into the operating system shell present an existential security and confidentiality hazard on dedicated Tier 0 management consoles.

### 1. Copilot Architecture & Tier 0 Confidentiality Hazards
Windows Copilot is designed to ingest contextual workspace data to assist users:
* **Clipboard and Screen Parsing**: Copilot hooks can analyze active window contents, desktop snapshots, and clipboard memory buffers. On a PAW, clipboard contents routinely contain administrative commands, LDAPS query strings, temporary passwords, or base64-encoded certificate requests.
* **External Cloud LLM Communication**: Copilot requires persistent outbound network sessions to Microsoft cloud AI infrastructure. Permitting external AI telemetry or prompt processing from a PAW completely shatters the network isolation boundary required for Tier 0 environments.
* **Prompt Injection and Inference Tampering**: Malicious content encountered during administrative tasks (e.g., untrusted log entries or user-supplied directory attributes) could theoretically be ingested by automated AI shims, presenting novel prompt injection or context confusion attack vectors.

### 2. Strict Prohibition on PAW Consoles
* **Enforcing Pure Administrative Isolation**: PAWs must be completely stripped of non-essential AI services, consumer integrations, and automated cloud sync agents.
* **Disabling UI and Background Shims**: Setting `TurnOffWindowsCopilot = 1` across user and computer policies disables the Copilot sidebar, removes the taskbar icon, suppresses the `Win + C` hotkey, and unregisters the background AI orchestration service.
* **Zero Disruption to Core Tooling**: Native administrative consoles (PowerShell, RSAT, Active Directory Administrative Center) run independently and do not rely on Copilot.

### 3. MITRE ATT&CK Mapping
* **T1005 - Data from Local System**: Accidental ingestion or exfiltration of sensitive administrative data.
* **T1048 - Exfiltration Over Alternative Protocol: Exfiltration to Cloud Storage**: Outbound transmission of administrative context to cloud AI endpoints.
* **T1115 - Clipboard Data**: Scraping administrative credentials or tokens from the system clipboard.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: AI assistants are strictly prohibited on PAWs by design. Disabling Copilot aligns directly with Microsoft Privileged Access Workstation hardening specifications.
* **Zero Operational Disruption**: Legitimate Active Directory administration, certificate authority operations, and PowerShell automation are completely unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Windows Copilot`
  * **Turn off Windows Copilot**: Set to **Enabled**
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Copilot`
  * **Turn off Windows Copilot**: Set to **Enabled**

4. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Windows Copilot on the PAW console:

[Download Script: Configure-PawUpwindowscopilot.ps1](../implementation_scripts/Configure-PawUpwindowscopilot.ps1)

```powershell
# Configure-PawUpwindowscopilot.ps1
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

[Download Script: Get-PawUpwindowscopilotStatus.ps1](../audit_scripts/Get-PawUpwindowscopilotStatus.ps1)

```powershell
# Get-PawUpwindowscopilotStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and disabling generative AI desktop integration)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and AI Surface Suppression
