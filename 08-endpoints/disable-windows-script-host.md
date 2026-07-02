# [REQ-END-034] Disable Windows Script Host and Remap Scripting Extensions

## Target Scope
* **Applicable Systems**: Member Workstations (Endpoints)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path (WSH Disable)**: Computer Configuration\Preferences\Windows Settings\Registry
  * **GPO Path (Associations)**: User Configuration\Preferences\Control Panel Settings\Folder Options
  * **Registry Location**:
    * `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`
      * `Enabled` = `0` (REG_DWORD)
    * `HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings`
      * `Enabled` = `0` (REG_DWORD)

---

## Rationale
Windows Script Host (WSH), which executes VBScript and JScript files (`wscript.exe` and `cscript.exe`), is frequently targeted by threat actors in phishing campaigns and initial access vectors. By placing a script file (e.g., `.vbs`, `.js`, `.wsf`, `.hta`) in an email attachment or download path, attackers can execute arbitrary code on the system if a user opens the file.

Enforcing these deactivation controls ensures:
1. **Attack Surface Reduction**: Disabling WSH globally blocks the execution of JScript and VBScript files via the standard scripting engines on the workstation.
2. **Defense-in-Depth File Associations**: Remapping the default file handler for typical scripting extensions to `notepad.exe` ensures that if a scripting file is double-clicked by an administrator or user, the file opens as plaintext in Notepad for inspection rather than executing its contents.

---

## Legacy Impact & Compatibility
* **Script Dependencies**: Any legacy administrative scripts (such as logon scripts or backup routines) written in VBScript or JScript will fail to run. All internal workstation management scripts must be written in PowerShell 5.1+ and executed under secure execution policies.
* **Explorer Associations**: Double-clicking on a `.js` or `.vbs` configuration file will open Notepad instead of running the script.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Disable WSH via GPO Registry Preferences
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoint GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create a new **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `Enabled`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`

#### Step 2: Configure Script File Extensions to Open in Notepad
1. Navigate to: `User Configuration\Preferences\Control Panel Settings\Folder Options`
2. Right-click and select **New -> Open With**:
   * **File Extension**: `vbs`
   * **Associated Program**: `%SystemRoot%\System32\notepad.exe`
   * **Set as default**: Check
3. Repeat the process for the following extensions: `vbe`, `js`, `jse`, `wsf`, `wsh`, `hta`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the local registry settings to disable WSH and remap associations.

[Download Script: Disable-Wsh.ps1](implementation_scripts/Disable-Wsh.ps1)

```powershell
# Disable-Wsh.ps1
# Description: Disables Windows Script Host globally in HKLM and HKCU registry hives, and remaps script file associations to Notepad.

Write-Host "Applying Windows Script Host and file association hardening..." -ForegroundColor Cyan

# 1. Disable WSH globally
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHklm)) {
    New-Item -Path $RegistryHklm -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHklm -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "[+] WSH globally disabled in HKLM." -ForegroundColor Green

$RegistryHkcu = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHkcu)) {
    New-Item -Path $RegistryHkcu -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHkcu -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "[+] WSH disabled in current user HKCU hive." -ForegroundColor Green

# 2. Remap script file extensions to notepad
$Extensions = @("vbs", "vbe", "js", "jse", "wsf", "wsh", "hta")
foreach ($Ext in $Extensions) {
    $ProgIdPath = "HKLM:\SOFTWARE\Classes\.$Ext"
    
    # Update Class Association to Notepad
    if (-not (Test-Path $ProgIdPath)) {
        New-Item -Path $ProgIdPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ProgIdPath -Name "" -Value "txtfile" -Type String -Force
    Write-Host "    Mapped .$Ext extension to txtfile handler." -ForegroundColor Gray
}
Write-Host "[+] Script file extension handlers mapped to Notepad." -ForegroundColor Green
```

*To verify the WSH configuration state:*

[Download Script: Get-WshStatus.ps1](audit_scripts/Get-WshStatus.ps1)

```powershell
# Get-WshStatus.ps1
# Description: Audits Windows Script Host registry state and script file extension association handlers.

Write-Host "--- Auditing Windows Script Host Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit WSH Registry settings
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (Test-Path $RegistryHklm) {
    $ValHklm = (Get-ItemProperty -Path $RegistryHklm -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($ValHklm -eq 0) {
        Write-Host "    - HKLM WSH Enabled: 0 (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: HKLM WSH is enabled or not configured (Value: '$ValHklm')" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - VULNERABLE: HKLM WSH settings key is missing (Expected: Enabled = 0)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit file associations
$Extensions = @("vbs", "vbe", "js", "jse", "wsf", "wsh", "hta")
foreach ($Ext in $Extensions) {
    $ProgIdPath = "HKLM:\SOFTWARE\Classes\.$Ext"
    if (Test-Path $ProgIdPath) {
        $Handler = (Get-ItemProperty -Path $ProgIdPath -Name "" -ErrorAction SilentlyContinue).""
        if ($Handler -eq "txtfile" -or $Handler -match "notepad") {
            Write-Host "    - Extension .$Ext Handler: $Handler (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: Extension .$Ext Handler is '$Handler' (Expected: txtfile/notepad)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: Extension .$Ext Class Registry key not found." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations on workstation OS minimization and script execution control.
* **DoD Windows 11 Computer STIG v2r6**: V-219661 (Windows Script Host disablement and script restriction).
* **CIS Microsoft Windows Client Benchmark**: Section 18.9 (Administrative templates for script execution safety).
