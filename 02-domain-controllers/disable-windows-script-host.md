# [REQ-DC-159] Disable Windows Script Host and Remap Scripting Extensions on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers and Member Servers (Tier 0 Identity Infrastructure). *(For Tier 0 Privileged Access Workstations, refer to [REQ-PAW-034](../07-paws/disable-windows-script-host.md); for Tier 2 Client Workstations, refer to [REQ-END-034](../08-endpoints/disable-windows-script-host.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025.

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
Domain Controllers host the Active Directory directory database (`NTDS.dit`), Kerberos ticket-granting service keys (`krbtgt`), and credentials for all domain identities. Protecting these Tier 0 identity stores requires aggressive operating system minimization and the systematic neutralization of Living-off-the-Land Binaries (LOLBins / LOLBAS) that adversaries leverage during post-exploitation, lateral movement, and defense evasion:

1. **Mitigation of LOLBin Abuse on Critical Servers**: Windows Script Host binaries (`cscript.exe` and `wscript.exe`) execute legacy VBScript (`vbscript.dll`) and JScript (`jscript.dll`) engines. Threat actors targeting Domain Controllers frequently invoke `cscript.exe` or `mshta.exe` to execute obfuscated staging scripts, query Active Directory via legacy ADSI/WMI interfaces, or execute memory injection routines while attempting to evade standard binary application allowlisting (MITRE ATT&CK T1059.005, T1059.007, T1218).
2. **Elimination of Untrusted Script Execution**: Disabling WSH system-wide via the `Enabled = 0` registry setting prevents the execution of all `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, and `.wsh` files through the primary scripting host, returning an immediate administrative blocking error.
3. **Comprehensive 64-Bit and 32-Bit WOW6432Node Coverage**: In 64-bit Windows Server environments, threat actors often invoke 32-bit binaries (`%SystemRoot%\SysWOW64\cscript.exe` or `wscript.exe`) to evade 64-bit security monitoring tools and API hooks. Configuring `Enabled = 0` and `TrustPolicy = 2` across both the native 64-bit registry branch (`HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`) and the 32-bit subsystem branch (`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings`) closes this evasion vector.
4. **TrustPolicy Hardening**: Setting `TrustPolicy = 2` enforces restrictions that disallow untrusted scripts system-wide, establishing defense-in-depth even if individual registry keys are tampered with.
5. **Accidental Double-Click Prevention**: Remapping legacy scripting extensions (`.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.hta`) to `txtfile` (`notepad.exe`) ensures that if an administrator inspects an administrative script or diagnostic file on the DC console, opening the file in Windows Explorer displays plain text in Notepad rather than silently triggering code execution.

---

## Legacy Impact & Compatibility
* **Software Licensing Management Tool (`slmgr.vbs`)**:
  * The Windows Software Licensing Management Tool (`slmgr.vbs`) is implemented as a VBScript script executed by `cscript.exe`. Disabling Windows Script Host prevents direct execution of `slmgr.vbs` from the command line (e.g., `slmgr.vbs /dli` or `slmgr.vbs /ato` will display an error stating that WSH is disabled).
  * **Enterprise Recommended Solution - Active Directory-Based Activation (ADBA)**: In enterprise Active Directory environments, Domain Controllers and domain-joined Windows Server instances should utilize **Active Directory-Based Activation (ADBA)**. With ADBA, activation objects are stored directly within the Active Directory forest configuration partition (`CN=Activation Objects,CN=Microsoft Technologies,CN=Services,CN=Configuration,DC=...`). Domain Controllers automatically activate upon promotion and domain membership verification without requiring local `slmgr.vbs` execution.
  * **Key Management Service (KMS)**: Environments utilizing centralized KMS host activation handle periodic volume license renewals through the background Software Protection Service (`sppsvc.exe`), requiring no manual `slmgr.vbs` interaction.
  * **Native PowerShell CIM License Verification**: Administrators can query licensing and activation status natively in PowerShell without relying on `slmgr.vbs` by inspecting the `SoftwareLicensingProduct` CIM class: `Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL" | Select-Object Name, ApplicationId, LicenseStatus, Description`.
  * **Manual Staging Workflow (One-Off MAK Activation)**: If a standalone or non-ADBA Domain Controller requires manual Multiple Activation Key (MAK) entry during initial bare-metal staging, administrators can temporarily enable WSH (`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 1`), perform `cscript.exe C:\Windows\System32\slmgr.vbs /ipk <ProductKey>` and `slmgr.vbs /ato`, and immediately re-lock WSH by restoring `Enabled = 0`.
* **Active Directory Core Services**:
  * Core Active Directory Domain Services (NTDS), Kerberos Key Distribution Center (KDC), DNS Server service, LDAP/LDAPS services, DFS Replication (DFSR), and Group Policy processing (`gpsvc.dll`) are compiled native C/C++ services and binaries that have zero dependency on Windows Script Host. Disabling WSH has no impact on directory replication, authentication, or group policy propagation.
* **SYSVOL Logon Scripts**:
  * Legacy logon scripts placed in the `SYSVOL` `netlogon` share written in VBScript execute on client workstations (endpoints), not on the Domain Controller itself. However, organizations should systematically modernize legacy `.vbs` logon scripts to PowerShell 5.1+ or native Group Policy Preferences (GPP) to ensure compatibility with hardened endpoint and PAW baselines.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Disable WSH via GPO Computer Preferences
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Domain Controller GPO (e.g., `GPO_Hardening_DomainControllers`).
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
3. Repeat for `vbe`, `js`, `jse`, `wsf`, `wsh`, and `hta`.
4. Alternatively, configure system-wide registry preferences under `HKLM\SOFTWARE\Classes\.<ext>` setting the default string value to `txtfile`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the local registry settings to disable WSH and remap associations.

[Download Script: Disable-DcWsh.ps1](implementation_scripts/Disable-DcWsh.ps1)

```powershell
# Disable-DcWsh.ps1
# Description: Disables Windows Script Host globally across 64-bit and 32-bit registry hives, enforces TrustPolicy, and remaps script file associations to Notepad on Domain Controllers.

Write-Host "Applying Windows Script Host and file association hardening for Domain Controllers..." -ForegroundColor Cyan

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
Write-Host "[i] Note: Software Licensing Management Tool (slmgr.vbs) requires ADBA or KMS. Use Get-CimInstance SoftwareLicensingProduct for querying status." -ForegroundColor Yellow
```

*To verify the WSH configuration state:*

[Download Script: Get-DcWshStatus.ps1](audit_scripts/Get-DcWshStatus.ps1)

```powershell
# Get-DcWshStatus.ps1
# Description: Audits Windows Script Host registry state across 64-bit and 32-bit hives and script file extension association handlers on Domain Controllers.

Write-Host "--- Auditing Windows Script Host Hardening on Domain Controllers ---" -ForegroundColor Cyan

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
    Write-Host "[-] Audit Result: VULNERABLE - Windows Script Host hardening controls on Domain Controller do not meet baseline requirements." -ForegroundColor Red
} else {
    Write-Host "[+] Audit Result: SECURE - Windows Script Host hardening controls on Domain Controller are fully compliant." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations Section 3.1.2 (System hardening and OS minimization) / DAT-NT-13 Note Technique.
* **DoD Windows Server STIG**: Requirements for unauthorized software and script execution control.
* **DoD Windows 11 Computer STIG v2r6**: Rule `V-219661` (Windows Script Host must be disabled).
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (Administrative Templates: System - Script Execution Restrictions).
* **Microsoft Learn**: Active Directory-Based Activation Overview and Software Licensing CIM Provider.
