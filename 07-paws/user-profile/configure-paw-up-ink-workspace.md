# [REQ-PAW-151] User Profile: Restrict Windows Ink Workspace on Lock Screen for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-162](../../08-endpoints/user-profile/configure-end-up-ink-workspace.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) serve as the dedicated management boundary for Active Directory forest infrastructure. In a PAW environment, the interactive console must remain completely locked against unauthenticated input, secondary application launching, or cached memory viewing when not actively in use by an authenticated administrator.

### 1. Windows Ink Architecture & Lock Screen Vulnerabilities
The Windows Ink Workspace enables digital pens, touch tablets, and styluses to interact with Windows drawing tools:
* When allowed to execute above the lock screen, the operating system launches Whiteboard or Sticky Notes within the unauthenticated session context (`LogonUI.exe`).
* On a PAW console, an administrator may jot down temporary operational notes, ticket numbers, or forest architecture details during administrative work.
* If ink tools can be invoked above lock, an unauthorized physical individual who gains access to the PAW hardware can launch Whiteboard or Sticky Notes with a single click of a digital stylus and review sensitive administrative notes without authenticating.
* Furthermore, executing modern app runtimes above the lock screen expands the code execution surface exposed to physical attackers attempting lock screen sandbox escapes.

### 2. Tier 0 Physical Security & Lock Screen Isolation
* **Impenetrable Authentication Barrier**: Setting `AllowWindowsInkWorkspace = 1` enforces the policy "On, but disallow access above lock".
* This guarantees that any stylus interactions, shortcut clicks, or touch gestures while the PAW is locked are ignored or immediately redirect the user to the Windows authentication prompt.
* Administrative users on touchscreen or pen-enabled PAW devices (such as administrative field laptops) can continue to use digital ink inside their authenticated sessions without compromising physical security.

### 3. MITRE ATT&CK Mapping
* **T1204 - User Execution**: Launching application interfaces above the lock screen.
* **T1056 - Input Capture: Shoulder Surfing**: Accessing cached administrative notes on unauthenticated displays.
* **T1552 - Unsecured Credentials**: Exploiting administrative notes or password fragments stored in Sticky Notes.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs do not require digital ink tools on the lock screen. Inside authenticated sessions, pen and touch hardware operate normally.
* **Zero Operational Disruption**: Legitimate Active Directory administration, RSAT tooling, and PowerShell workflows function with zero disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Ink Workspace`
4. Double-click **Allow Windows Ink Workspace** and configure:
   * Select **Enabled**
   * In the **Options** drop-down menu, select: **On, but disallow access above lock**
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to restrict Windows Ink Workspace access above the lock screen on the PAW console:

[Download Script: Configure-PawAuditInkworkspace.ps1](../implementation_scripts/Configure-PawAuditInkworkspace.ps1)

```powershell
# Configure-PawAuditInkworkspace.ps1
Write-Host "Enforcing System Mitigation control: ink-workspace..." -ForegroundColor Cyan

# Set Registry value: AllowWindowsInkWorkspace
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 1 -Type DWord -Force
Write-Host "    Enforced AllowWindowsInkWorkspace = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditInkworkspaceStatus.ps1](../audit_scripts/Get-PawAuditInkworkspaceStatus.ps1)

```powershell
# Get-PawAuditInkworkspaceStatus.ps1
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
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and Physical Security
