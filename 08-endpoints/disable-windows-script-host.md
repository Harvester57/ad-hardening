# [REQ-END-034] Disable Windows Script Host and Remap Scripting Extensions

## Target Scope
* **Applicable Systems**: Member Workstations (Endpoints - Tier 2 Client Workstations and Laptops). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-034](../07-paws/disable-windows-script-host.md); for Tier 0 Domain Controllers and Member Servers, refer to [REQ-DC-159](../02-domain-controllers/disable-windows-script-host.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809+), Windows 11 Enterprise (all supported builds).

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **GPO Path (WSH Disable)**: Computer Configuration\Preferences\Windows Settings\Registry
  * **GPO Path (User Hive)**: User Configuration\Preferences\Windows Settings\Registry
  * **GPO Path (Associations)**: User Configuration\Preferences\Control Panel Settings\Folder Options
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`
      * `Enabled` = `0` (REG_DWORD)
      * `TrustPolicy` = `2` (REG_DWORD)
    * `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings`
      * `Enabled` = `0` (REG_DWORD)
      * `TrustPolicy` = `2` (REG_DWORD)
    * `HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings`
      * `Enabled` = `0` (REG_DWORD)
      * `TrustPolicy` = `2` (REG_DWORD)
    * `HKLM\SOFTWARE\Classes\.<ext>` (where `<ext>` = `vbs`, `vbe`, `js`, `jse`, `wsf`, `wsh`, `hta`)
      * `(Default)` = `txtfile` (REG_SZ)

---

## Rationale
Windows Script Host (WSH), encompassing the `wscript.exe` (graphical) and `cscript.exe` (command-line) host engines, executes legacy scripting languages including VBScript (`vbscript.dll`) and JScript (`jscript.dll`). In client endpoint environments, WSH is one of the most heavily abused Living-off-the-Land Binaries (LOLBins / LOLBAS) leveraged by adversaries for initial access, defense evasion, and payload execution (MITRE ATT&CK T1059.005, T1059.007, T1218):

1. **Initial Access via Phishing and Drive-By Downloads**: Threat actors routinely deliver weaponized script files (such as `.vbs`, `.js`, `.wsf`, `.hta`) disguised as business invoices, delivery notifications, or archived attachments inside ZIP/ISO files. When an unsuspecting user double-clicks such a file, Windows Explorer automatically invokes `wscript.exe` or `mshta.exe`, running malicious code directly in the user's security context without prompting.
2. **Attack Surface Reduction**: Disabling WSH globally via the `Enabled = 0` registry parameter completely blocks `wscript.exe` and `cscript.exe` from executing any VBScript or JScript files system-wide, producing an immediate termination notice if an execution attempt is made.
3. **64-Bit and 32-Bit WOW6432Node Coverage**: On 64-bit Windows architectures, 32-bit applications and sub-processes invoke the 32-bit scripting host located in `%SystemRoot%\SysWOW64\wscript.exe`. Applying the `Enabled = 0` and `TrustPolicy = 2` registry values to both the native 64-bit hive (`HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`) and the 32-bit registry hive (`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings`) guarantees that 32-bit sub-processes cannot be weaponized as an evasion tactic.
4. **TrustPolicy Hardening**: Setting `TrustPolicy = 2` enforces script restriction policies to disallow untrusted or unsigned scripts, providing defense-in-depth even if individual components attempt to execute outside the primary WSH engine.
5. **Defense-in-Depth File Association Remapping**: Setting default file associations for legacy script extensions (`.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.hta`) to `txtfile` (`notepad.exe`) ensures that if a script file is double-clicked in Windows Explorer, it opens harmlessly in Notepad for plain-text inspection rather than executing code.

---

## Legacy Impact & Compatibility
* **Legacy Logon Scripts**: Any legacy administrative logon or logoff scripts written in VBScript (`.vbs`) or JScript (`.js`) will fail to run. All enterprise workstation management scripts must be modernized to PowerShell 5.1+ running under restricted or RemoteSigned execution policies, or replaced by native Group Policy Preferences (GPP).
* **Third-Party Software Installers**: Certain legacy commercial software installers or custom internal packages that invoke `cscript.exe` during setup will encounter execution errors. Packaging routines must be updated to native MSI, WiX, or modern PowerShell deployments.
* **Windows Explorer File Associations**: Double-clicking on any `.vbs`, `.js`, or `.wsf` file will open Notepad displaying the script source text rather than running the script engine.
* **Windows Script Host Execution Dialog**: If a user or background process attempts to call `wscript.exe` or `cscript.exe`, Windows displays a notification stating: *"Windows Script Host access is disabled on this machine. Contact your administrator for details."*

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Disable WSH via GPO Computer Preferences
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoint GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create a new **Registry Item** for the native 64-bit hive:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `Enabled`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`
5. Create a second **Registry Item** for `TrustPolicy`:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `TrustPolicy`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `2`
6. Create a third **Registry Item** for 32-bit WOW64 disablement:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `Enabled`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`
7. Create a fourth **Registry Item** for 32-bit WOW64 TrustPolicy:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `TrustPolicy`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `2`

#### Step 2: Disable WSH in User Configuration Preferences
1. Navigate to: `User Configuration\Preferences\Windows Settings\Registry`
2. Create a new **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_CURRENT_USER`
   * **Key Path**: `SOFTWARE\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `Enabled`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`
3. Create a second **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_CURRENT_USER`
   * **Key Path**: `SOFTWARE\Microsoft\Windows Script Host\Settings`
   * **Value Name**: `TrustPolicy`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `2`

#### Step 3: Remap Script File Extensions to Notepad
1. Navigate to: `User Configuration\Preferences\Control Panel Settings\Folder Options`
2. Right-click and select **New -> Open With**:
   * **File Extension**: `vbs`
   * **Associated Program**: `%SystemRoot%\System32\notepad.exe`
   * **Set as default**: Check
3. Repeat for the remaining extensions: `vbe`, `js`, `jse`, `wsf`, `wsh`, and `hta`.
4. Alternatively, configure system-wide registry preferences under `HKLM\SOFTWARE\Classes\.<ext>` setting the default string value to `txtfile`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the local registry settings to disable WSH and remap associations.

[Download Script: Disable-Wsh.ps1](implementation_scripts/Disable-Wsh.ps1)

```powershell
# Disable-Wsh.ps1
# Description: Disables Windows Script Host globally across 64-bit and 32-bit registry hives, enforces TrustPolicy, and remaps script file associations to Notepad.

Write-Host "Applying Windows Script Host and file association hardening..." -ForegroundColor Cyan

# 1. Disable WSH globally in 64-bit HKLM
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHklm)) {
    New-Item -Path $RegistryHklm -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHklm -Name "Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RegistryHklm -Name "TrustPolicy" -Value 2 -Type DWord -Force
Write-Host "[+] WSH globally disabled and TrustPolicy enforced in HKLM." -ForegroundColor Green

# 2. Disable WSH in WOW6432Node on 64-bit systems
if ([Environment]::Is64BitOperatingSystem) {
    $RegistryWow64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings"
    if (-not (Test-Path $RegistryWow64)) {
        New-Item -Path $RegistryWow64 -Force | Out-Null
    }
    Set-ItemProperty -Path $RegistryWow64 -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $RegistryWow64 -Name "TrustPolicy" -Value 2 -Type DWord -Force
    Write-Host "[+] WSH globally disabled and TrustPolicy enforced in HKLM WOW6432Node." -ForegroundColor Green
}

# 3. Disable WSH in current user HKCU hive
$RegistryHkcu = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHkcu)) {
    New-Item -Path $RegistryHkcu -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHkcu -Name "Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RegistryHkcu -Name "TrustPolicy" -Value 2 -Type DWord -Force
Write-Host "[+] WSH disabled in current user HKCU hive." -ForegroundColor Green

# 4. Remap script file extensions to notepad
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
# Description: Audits Windows Script Host registry state across 64-bit and 32-bit hives and script file extension association handlers.

Write-Host "--- Auditing Windows Script Host Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit WSH Registry settings in 64-bit HKLM
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (Test-Path $RegistryHklm) {
    $ValHklm = (Get-ItemProperty -Path $RegistryHklm -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($ValHklm -eq 0) {
        Write-Host "    - HKLM WSH Enabled: 0 (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: HKLM WSH is enabled or not configured (Value: '$($ValHklm)')" -ForegroundColor Red
        $script:Vulnerable = $true
    }

    $TrustHklm = (Get-ItemProperty -Path $RegistryHklm -Name "TrustPolicy" -ErrorAction SilentlyContinue).TrustPolicy
    if ($TrustHklm -eq 2) {
        Write-Host "    - HKLM WSH TrustPolicy: 2 (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: HKLM WSH TrustPolicy is not set to 2 (Value: '$($TrustHklm)')" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - VULNERABLE: HKLM WSH settings key is missing (Expected: Enabled = 0, TrustPolicy = 2)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit WSH Registry settings in WOW6432Node on 64-bit systems
if ([Environment]::Is64BitOperatingSystem) {
    $RegistryWow64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings"
    if (Test-Path $RegistryWow64) {
        $ValWow64 = (Get-ItemProperty -Path $RegistryWow64 -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        if ($ValWow64 -eq 0) {
            Write-Host "    - WOW6432Node WSH Enabled: 0 (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: WOW6432Node WSH is enabled or not configured (Value: '$($ValWow64)')" -ForegroundColor Red
            $script:Vulnerable = $true
        }

        $TrustWow64 = (Get-ItemProperty -Path $RegistryWow64 -Name "TrustPolicy" -ErrorAction SilentlyContinue).TrustPolicy
        if ($TrustWow64 -eq 2) {
            Write-Host "    - WOW6432Node WSH TrustPolicy: 2 (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: WOW6432Node WSH TrustPolicy is not set to 2 (Value: '$($TrustWow64)')" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: WOW6432Node WSH settings key is missing (Expected: Enabled = 0, TrustPolicy = 2)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 3. Audit file associations
$Extensions = @("vbs", "vbe", "js", "jse", "wsf", "wsh", "hta")
foreach ($Ext in $Extensions) {
    $ProgIdPath = "HKLM:\SOFTWARE\Classes\.$Ext"
    if (Test-Path $ProgIdPath) {
        $Handler = (Get-ItemProperty -Path $ProgIdPath -Name "" -ErrorAction SilentlyContinue).""
        if ($Handler -eq "txtfile" -or $Handler -match "notepad") {
            Write-Host "    - Extension .$Ext Handler: $Handler (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: Extension .$Ext Handler is '$($Handler)' (Expected: txtfile/notepad)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: Extension .$Ext Class Registry key not found." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "[-] Audit Result: VULNERABLE - Windows Script Host hardening controls do not meet baseline requirements." -ForegroundColor Red
} else {
    Write-Host "[+] Audit Result: SECURE - Windows Script Host hardening controls are fully compliant." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations Section 3.1.2 (System hardening and OS minimization) / DAT-NT-13 Note Technique.
* **DoD Windows 11 Computer STIG v2r6**: Rule `V-219661` (Windows Script Host must be disabled).
* **DoD Windows 10 Computer STIG**: Rule `V-63825` (Configure Windows Script Host to prevent execution of untrusted scripts).
* **CIS Microsoft Windows Client Benchmark**: Section 18.9 (Administrative Templates: System - Script Execution Restrictions).
* **Microsoft Learn**: Windows Script Host Settings and Security Guidelines.
