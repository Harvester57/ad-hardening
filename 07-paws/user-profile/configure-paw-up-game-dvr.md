# [REQ-PAW-150] User Profile: Disable Windows Game DVR for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-161](../../08-endpoints/user-profile/configure-end-up-game-dvr.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Disable Windows Game Recording and Broadcasting**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Game Recording and Broadcasting\Enables or disables Windows Game Recording and Broadcasting` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR`
    * Value Name: `AllowGameDVR`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Strictly prohibit Game DVR and broadcast APIs)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated exclusively to managing Tier 0 Active Directory infrastructure, where administrators interact with domain controllers, certificate templates, and password vaulting solutions. Allowing consumer multimedia recording subsystems (such as Game DVR and the Windows Game Bar) to run on a PAW console creates an intolerable risk of unmonitored administrative session capture and credential exposure.

### 1. Game DVR Architecture & Surveillance Risks on PAWs
The Windows Game Recording and Broadcasting subsystem provides background screen capture APIs:
* When active, background processes (`bcastdvr.exe`) hook the graphics subsystem to record desktop sessions into temporary rolling buffers.
* On a PAW console, an administrator's screen displays highly sensitive information: Active Directory schema updates, enterprise group memberships, password reset dialogues, and Kerberos ticket operations.
* If Game DVR is available, malicious software, unauthorized administrative scripts, or accidental key combinations (`Win + G` / `Win + Alt + R`) can capture high-resolution desktop video into local user directories.
* An attacker with local read access could harvest these unencrypted MP4 recordings to analyze directory architectures, observe administrative procedures, or visually extract credentials.

### 2. Tier 0 Architectural Purity & Surface Elimination
* **Strict Software Footprint Minimization**: Dedicated PAW consoles must eliminate all gaming, streaming, and entertainment features.
* **Neutralizing Media Broadcast APIs**: Disabling Game DVR terminates the underlying recording service, closes down broadcast interfaces, and prevents accidental keyboard activation.
* **Preserving Dedicated CPU/GPU Resources**: Eliminates background multimedia hooks, ensuring maximum stability and responsiveness for mission-critical management consoles.

### 3. MITRE ATT&CK Mapping
* **T1113 - Screen Capture**: Recording sensitive administrative sessions via native capture frameworks.
* **T1125 - Video Capture**: Continuous background video recording of administrative console activities.
* **T1059 - Command and Scripting Interpreter**: Scripting media capture routines via native platform shims.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Gaming and streaming tools are strictly prohibited on PAWs by design. Disabling Game DVR causes zero disruption to administrative tasks.
* **Zero Disruption**: RSAT tools, PowerShell scripts, and Active Directory administrative consoles operate without dependency on Game DVR.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Game Recording and Broadcasting`
4. Double-click **Enables or disables Windows Game Recording and Broadcasting** and set it to **Disabled**.
   *(Note: Setting this policy to Disabled enforces AllowGameDVR = 0).*
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Windows Game DVR on the PAW console:

[Download Script: Configure-PawAuditGamedvr.ps1](../implementation_scripts/Configure-PawAuditGamedvr.ps1)

```powershell
# Configure-PawAuditGamedvr.ps1
Write-Host "Enforcing System Mitigation control: game-dvr..." -ForegroundColor Cyan

# Set Registry value: AllowGameDVR
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
Write-Host "    Enforced AllowGameDVR = 0" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditGamedvrStatus.ps1](../audit_scripts/Get-PawAuditGamedvrStatus.ps1)

```powershell
# Get-PawAuditGamedvrStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and disabling unnecessary multimedia capture services)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and Media Subsystem Lockdown
