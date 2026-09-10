# [REQ-END-162] User Profile: Restrict Windows Ink Workspace on Lock Screen for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-151](../../07-paws/user-profile/configure-paw-up-ink-workspace.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Restrict Windows Ink Workspace Access Above Lock Screen**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Ink Workspace\Allow Windows Ink Workspace` -> **Enabled**
    * GPO Dropdown Option: `On, but disallow access above lock`
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace`
    * Value Name: `AllowWindowsInkWorkspace`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / On, but disallow access above lock)

---

## Rationale
The Windows Ink Workspace provides digital pen and stylus input capabilities, offering productivity tools such as Sticky Notes, Whiteboard, and Snip & Sketch on touch-enabled devices and laptops. When unconstrained, Windows allows the Ink Workspace to be invoked while the device is locked—typically by clicking the shortcut button on an active digital stylus or tapping the lock screen icon.

### 1. Windows Ink Architecture & Lock Screen Vulnerabilities
When the Ink Workspace is accessible above the lock screen:
* The operating system instantiates drawing and note-taking interfaces inside the unauthenticated logon session (`LogonUI.exe`).
* Sticky Notes and Whiteboard sessions frequently retain cached user data, handwritten meeting notes, system hostnames, contact information, and temporary passcodes recorded during previous authenticated user sessions.
* An unauthorized physical bystander who picks up an unattended, locked enterprise tablet or laptop can click the digital pen button to open Sticky Notes and read confidential notes without authenticating.
* Furthermore, executing complex UWP drawing applications above lock increases the code surface exposed to physical attackers attempting sandbox breakouts or UI spoofing.

### 2. Physical Security & Lock Screen Hardening
* Setting `AllowWindowsInkWorkspace = 1` enforces the policy "On, but disallow access above lock".
* This allows enterprise users to fully utilize digital pen and inking capabilities within their authenticated desktop sessions, while ensuring that the lock screen remains an unbreachable authentication gate.
* Any pen button clicks or screen taps while the machine is locked are ignored or prompt the user to enter their PIN, password, or biometric credential before launching any app.

### 3. MITRE ATT&CK Mapping
* **T1204 - User Execution**: Launching interactive application interfaces above the lock screen.
* **T1056 - Input Capture: Shoulder Surfing**: Viewing cached notes, credentials, and meeting data on unauthenticated displays.
* **T1552 - Unsecured Credentials**: Exploiting credentials saved in Sticky Notes accessible without authentication.

---

## Legacy Impact & Compatibility
* **Stylus and Pen Functionality**: Digital pens, styluses, and drawing tablets continue to function normally inside authenticated user desktop sessions.
* **Touchscreen Devices**: Laptops, Surface tablets, and interactive kiosk displays retain full touch and inking capabilities without operational disruption.
* **Zero Disruption for Non-Pen Hardware**: Workstations and servers without pen or touch hardware are completely unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Ink Workspace`
4. Double-click **Allow Windows Ink Workspace** and configure:
   * Select **Enabled**
   * In the **Options** drop-down menu, select: **On, but disallow access above lock**
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to restrict Windows Ink Workspace access above the lock screen:

[Download Script: Configure-EndAuditInkworkspace.ps1](../implementation_scripts/Configure-EndAuditInkworkspace.ps1)

```powershell
# Configure-EndAuditInkworkspace.ps1
Write-Host "Enforcing System Mitigation control: ink-workspace..." -ForegroundColor Cyan

# Set Registry value: AllowWindowsInkWorkspace
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 1 -Type DWord -Force
Write-Host "    Enforced AllowWindowsInkWorkspace = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditInkworkspaceStatus.ps1](../audit_scripts/Get-EndAuditInkworkspaceStatus.ps1)

```powershell
# Get-EndAuditInkworkspaceStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: AllowWindowsInkWorkspace
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.AllowWindowsInkWorkspace -ne 1) {
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x (Windows Ink Workspace); CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000160, Windows 11 STIG Rule WN11-CC-000160
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and preventing lock screen bypasses)
* **Microsoft Security Guidance**: Windows Ink Workspace Administrative Policies and Lock Screen Protection
