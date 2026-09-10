# [REQ-END-161] User Profile: Disable Windows Game DVR for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-150](../../07-paws/user-profile/configure-paw-up-game-dvr.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Disable Windows Game Recording and Broadcasting**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Game Recording and Broadcasting\Enables or disables Windows Game Recording and Broadcasting` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR`
    * Value Name: `AllowGameDVR`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Completely turn off Game DVR and broadcast APIs)

---

## Rationale
Windows Game Recording and Broadcasting (Game DVR) is a consumer-oriented multimedia subsystem built into Windows 10 and 11. Designed to capture gaming clips, broadcast live gameplay, and maintain background rolling video buffers, the Game DVR subsystem introduces severe information disclosure risks, unmonitored desktop recording pathways, and unnecessary system resource utilization on enterprise workstations.

### 1. Game DVR Architecture & Continuous Capture Pipelines
When Game DVR is enabled on a Windows system:
* The background recording service (`bcastdvr.exe` and associated media platform shims) continuously monitors interactive applications and graphics display contexts.
* If background recording is enabled, the system maintains a rolling video buffer in memory and temporary disk cache, capturing screen frames, user mouse movements, audio feeds, and desktop notifications.
* These captured video files are stored in the user's `%UserProfile%\Videos\Captures` directory in standard unencrypted MP4 format with default user permissions.
* An attacker with user-level access, malicious script execution, or low-privilege malware can harvest these cached recordings to reconstruct sensitive business activities, view customer data, and extract credentials typed into masked password dialogs via visual timing analysis.

### 2. Threat Vectors & Enterprise Exposure
* **Covert Desktop Surveillance**: Threat actors can manipulate the Game DVR API or hotkeys (`Win + Alt + R`, `Win + G`) to trigger covert screen captures of confidential business applications without triggering traditional security alerts.
* **Unauthorized Streaming and Broadcasting**: Game DVR contains built-in broadcasting connectors intended for consumer streaming platforms. In enterprise networks, unconstrained broadcast agents can bypass data exfiltration monitoring.
* **Performance and Memory Overhead**: Continuous background desktop frame capture places steady demands on the CPU, GPU video encoding pipeline, and RAM, degrading the performance of enterprise workloads.
* Setting `AllowGameDVR = 0` (via GPO Disabled) terminates the recording service, unregisters the Game Bar background engine, and blocks all screen recording hooks.

### 3. MITRE ATT&CK Mapping
* **T1113 - Screen Capture**: Exploiting native recording frameworks to capture desktop frames and application windows.
* **T1125 - Video Capture**: Leveraging operating system video recording APIs for continuous surveillance.
* **T1059 - Command and Scripting Interpreter**: Scripting media capture routines via native platform shims.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Business productivity software, enterprise web applications, and administrative consoles have zero reliance on Game DVR. Disabling it has no adverse operational effects.
* **Legitimate Screen Recording**: Enterprise video recording and web conferencing tools (such as Microsoft Teams, Zoom, or Webex) utilize their own application-level capture APIs and remain fully functional.
* **Performance Gain**: Workstations benefit from reduced GPU and memory overhead by terminating background capture threads.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Game Recording and Broadcasting`
4. Double-click **Enables or disables Windows Game Recording and Broadcasting** and set it to **Disabled**.
   *(Note: Setting this policy to Disabled enforces AllowGameDVR = 0).*
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Windows Game DVR:

[Download Script: Configure-EndAuditGamedvr.ps1](../implementation_scripts/Configure-EndAuditGamedvr.ps1)

```powershell
# Configure-EndAuditGamedvr.ps1
Write-Host "Enforcing System Mitigation control: game-dvr..." -ForegroundColor Cyan

# Set Registry value: AllowGameDVR
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
Write-Host "    Enforced AllowGameDVR = 0" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditGamedvrStatus.ps1](../audit_scripts/Get-EndAuditGamedvrStatus.ps1)

```powershell
# Get-EndAuditGamedvrStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: AllowGameDVR
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.AllowGameDVR -ne 0) {
    $script:Vulnerable = $true
}

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x (Game DVR); CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000165, Windows 11 STIG Rule WN11-CC-000165
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing user profiles and disabling unnecessary multimedia capture services)
* **Microsoft Security Guidance**: Windows Game Recording and Broadcasting Policy Specifications
