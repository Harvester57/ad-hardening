# Hardening Requirement: Disable AutoPlay and AutoRun

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\AutoPlay Policies
  * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun

---

## Rationale
The AutoPlay and AutoRun features in Windows are designed to automatically execute programs or open media when a removable drive, network share, or CD-ROM is inserted or connected. 

Attackers exploit these features by placing malicious scripts, payloads, or executables on USB drives or external storage media. If AutoPlay is enabled, connecting the drive triggers automatic execution of these scripts or programs without user interaction or approval, allowing malware to achieve immediate execution in the context of the logged-on user. Disabling AutoPlay across all drive types completely mitigates this physical transmission vector.

---

## Legacy Impact & Compatibility
* **User Experience**: Users will not see pop-up choices or automated actions when connecting USB sticks, DVDs, or external drives. They must manually open File Explorer and navigate to the drive to read or open files.
* **Installer Media**: Software installers located on optical disks or external media will not start automatically; users must double-click the setup application manually.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\AutoPlay Policies`
4. Configure the following settings:
   * **Policy**: `Turn off AutoPlay`
   * **Setting**: `Enabled`
   * **Select Options**: `All drives`
   * **Policy**: `Set the default behavior for AutoRun`
   * **Setting**: `Enabled`
   * **Select Options**: `Do not execute any autorun commands`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure Explorer registry keys to disable AutoPlay and AutoRun on all drive types.

[Download Script: Disable-AutoPlay.ps1](implementation_scripts/Disable-AutoPlay.ps1)

```powershell
# Disable-AutoPlay.ps1
# Disables AutoPlay/AutoRun registry settings globally on all drive types.

Write-Host "--- Disabling AutoPlay and AutoRun ---" -ForegroundColor Cyan

$ExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

if (-not (Test-Path $ExplorerPath)) {
    New-Item -Path $ExplorerPath -Force | Out-Null
}

# NoDriveTypeAutoRun = 0xFF (255 in decimal) disables AutoRun on all types of drives
Set-ItemProperty -Path $ExplorerPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# NoAutorun = 1 disables AutoRun commands in inf files
$SystemExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $SystemExplorerPath -Name "NoAutorun" -Value 1 -Type DWord

Write-Host "[+] AutoPlay and AutoRun registry parameters set." -ForegroundColor Green
```

*To audit AutoPlay configurations:*
[Download Script: Test-AutoPlay.ps1](audit_scripts/Test-AutoPlay.ps1)

```powershell
# Test-AutoPlay.ps1
# Audits local system registry parameters for AutoPlay status.

Write-Host "--- Auditing AutoPlay Configuration ---" -ForegroundColor Cyan

$ExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

$NoDriveAuto = Get-ItemProperty -Path $ExplorerPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
$NoAutoCmd = Get-ItemProperty -Path $ExplorerPath -Name "NoAutorun" -ErrorAction SilentlyContinue

$NoDriveVal = if ($NoDriveAuto) { $NoDriveAuto.NoDriveTypeAutoRun } else { 0 }
$NoAutoVal = if ($NoAutoCmd) { $NoAutoCmd.NoAutorun } else { 0 }

$NoDriveColor = if ($NoDriveVal -eq 255) { "Green" } else { "Red" }
$NoAutoColor = if ($NoAutoVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - NoDriveTypeAutoRun: $NoDriveVal (Required = 255 to disable all drives)" -ForegroundColor $NoDriveColor
Write-Host "    - NoAutorun: $NoAutoVal (Required = 1)" -ForegroundColor $NoAutoColor
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.3.1 (Turn off AutoPlay), Section 18.3.2 (Set the default behavior for AutoRun)
* **Microsoft Security Baselines**: Windows Client Explorer configuration standards.
