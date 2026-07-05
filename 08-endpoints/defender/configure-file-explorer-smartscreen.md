# [REQ-END-077] Configure File Explorer SmartScreen

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\File Explorer`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
      * `EnableSmartScreen` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
      * `ShellSmartScreenLevel` = `Block` (REG_SZ)

---

## Rationale
Windows Defender SmartScreen protects users from running unrecognized or potentially malicious applications downloaded from the internet. Configuring the level to 'Block' prevents users from bypassing security warnings.

---

## Legacy Impact & Compatibility
Users will be unable to run unrecognized custom scripts or executables without administrative approval.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\File Explorer
2. Set 'Configure Windows Defender SmartScreen' to 'Enabled'
3. Select 'Require approval from an administrator before running unrecognized software' under Options

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderSmartScreen.ps1](../implementation_scripts/Configure-DefenderSmartScreen.ps1)

```powershell
# Configure-DefenderSmartScreen.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "EnableSmartScreen" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "ShellSmartScreenLevel" -Value "Block" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderSmartScreenStatus.ps1](../audit_scripts/Get-DefenderSmartScreenStatus.ps1)

```powershell
# Get-DefenderSmartScreenStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (Test-Path $Path) {
    $Enable = Get-ItemProperty -Path $Path -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    $Level = Get-ItemProperty -Path $Path -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue
    if ($Enable -and $Enable.EnableSmartScreen -eq 1 -and $Level -and $Level.ShellSmartScreenLevel -eq "Block") {
        Write-Output "Compliant"
        exit 0
    }
}
Write-Output "Non-Compliant"
exit 1
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
