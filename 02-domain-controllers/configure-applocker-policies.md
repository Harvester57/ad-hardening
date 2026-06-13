# [REQ-DC-021] Configure AppLocker Policies on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Service Configuration (GPO)**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Application Identity` -> Automatic
  * **AppLocker Path (GPO)**: `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
  * **Registry Location (Service)**: `HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc` -> `Start` = `2` (REG_DWORD)
  * **Registry Location (Enforcement)**: `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

---

## Rationale
Domain Controllers are Tier 0 administrative assets and must never be used for general-purpose tasks like web browsing, document viewing, or running unapproved utilities. Attackers who compromise a Domain Controller or obtain administrative access often attempt to execute custom binaries, remote access tools (RATs), or script-based tools to pivot, establish persistence, or extract the Active Directory database (NTDS.dit).

Enforcing AppLocker policies on Domain Controllers provides the following defense-in-depth security benefits:
1. **Restricts Execution to Authorized Software**: Prevents execution of unapproved software, preventing standard user directories (such as `C:\Users\` or `C:\Windows\Temp\`) from being used to launch malicious binaries or scripts.
2. **Blocks Browser Execution**: Prevents administrative users from launching web browsers (Chrome, Edge, Firefox, Internet Explorer) directly on Domain Controllers, shutting down web-based drive-by downloads and browser-based credential leakage.
3. **Restricts Windows Installer and Script Execution**: Prevents unauthorized `.msi` installations and unauthorized PowerShell or VBScript scripts from running, reducing the likelihood of successful exploitation via living-off-the-land techniques.
4. **Defends Against AppLocker Bypasses**: Abusing trusted, signed Microsoft binaries (such as `msbuild.exe`, `installutil.exe`, `regasm.exe`, `regsvcs.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`) allows attackers to execute arbitrary code bypassing default AppLocker rules. This control blocks these "Living off the Land" binaries (LOLBins) and prevents execution from user-writeable paths under `%WINDIR%` (such as `Tasks`, `Temp`, `tracing`, `spool\drivers\color`, etc.).

---

## Legacy Impact & Compatibility
* **Third-Party Administrative Tools**: Monitoring agents, backup orchestrators, and system management tools that run from custom directories (outside `%ProgramFiles%` or `%WinDir%`) will be blocked unless explicit path, publisher, or hash rules are created to whitelist them.
* **Audit Mode Verification**: It is highly recommended to deploy AppLocker in **Audit Only** mode for a baseline period (e.g., 30 days) to identify all legitimate software and administrative scripts. Analyze the event log (`Applications and Services Logs\Microsoft\Windows\AppLocker`) to create the necessary whitelist rules before switching to **Enforce rules** mode.
* **AppIDSvc Service**: AppLocker relies on the **Application Identity** service (`AppIDSvc`) to evaluate rule enforcement. If the service is not running, rules will not be enforced.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Enable Application Identity Service
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting Domain Controllers (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Double-click **Application Identity**.
5. Select **Define this policy setting** and configure the startup mode to **Automatic**.

#### 2. Configure AppLocker Enforcement
1. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
2. Right-click **AppLocker** and select **Properties**.
3. Under the **Enforcement** tab, check **Configured** for the following rule collections:
   * **Executable rules** -> Select **Enforce rules** (or **Audit only** for baseline testing)
   * **Windows Installer rules** -> Select **Enforce rules** (or **Audit only**)
   * **Script rules** -> Select **Enforce rules** (or **Audit only**)
   * **Packaged app rules** -> Select **Enforce rules** (or **Audit only**)
4. Click **OK**.

#### 3. Create Default and Block Rules
1. Expand **AppLocker** and select **Executable Rules**.
2. Right-click **Executable Rules** and select **Create Default Rules** (allows all files in Windows and Program Files directories, and allows local Administrators to run all files).
3. To block LOLBins and writeable directories, create explicit **Deny** rules for **Everyone**:
   * **Writeable Directories (Path Rules)**:
     * Deny `%WINDIR%\Tasks\*`
     * Deny `%WINDIR%\Temp\*`
     * Deny `%WINDIR%\tracing\*`
     * Deny `%WINDIR%\System32\spool\drivers\color\*`
     * Deny `%WINDIR%\System32\Tasks\Microsoft\Windows\SyncCenter\*`
     * Deny `%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*`
   * **Bypass Binaries (Publisher or Path Rules)**:
     * Deny `*\msbuild.exe`
     * Deny `*\installutil.exe`
     * Deny `*\mshta.exe`
     * Deny `*\regasm.exe`
     * Deny `*\regsvcs.exe`
     * Deny `*\regsvr32.exe`
     * Deny `*\rundll32.exe`
     * Deny `*\bginfo.exe`
     * Deny `*\cdb.exe`
     * Deny `*\cmstp.exe`
     * Deny `*\control.exe`
     * Deny `*\csi.exe`
     * Deny `*\dfsvc.exe`
     * Deny `*\dnx.exe`
     * Deny `*\fsi.exe`
     * Deny `*\ie4unit.exe`
     * Deny `*\ieexec.exe`
     * Deny `*\infdefaultinstall.exe`
     * Deny `*\mavinject.exe`
     * Deny `*\msdeploy.exe`
     * Deny `*\msdt.exe`
     * Deny `*\msxsl.exe`
     * Deny `*\odbcconf.exe`
     * Deny `*\presentationhost.exe`
     * Deny `*\rcsi.exe`
     * Deny `*\rsi.exe`
     * Deny `*\runscripthelper.exe`
     * Deny `*\te.exe`
     * Deny `*\tracker.exe`
     * Deny `*\xwizard.exe`
4. Repeat the process for **Script Rules** by creating default rules and adding Deny rules for script execution from the same user-writeable paths (such as `%WINDIR%\Temp\*` and `%WINDIR%\Tasks\*`).
5. Disable NTVDM (16-bit application support) to prevent AppLocker bypasses via 16-bit binaries:
   * Navigate to: `Computer Configuration\Administrative Templates\System\16-bit Application Compatibility`
   * Configure **Prevent access to 16-bit applications** to **Enabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure the Application Identity service and import a robust local AppLocker policy.

[Download Script: Set-AppLockerDCPolicy.ps1](implementation_scripts/Set-AppLockerDCPolicy.ps1)

```powershell
# Set-AppLockerDCPolicy.ps1
# Description: Configures the Application Identity service and imports a robust local AppLocker XML policy.

Write-Host "Applying hardening requirement: Configure AppLocker on Domain Controllers..." -ForegroundColor Cyan

# 1. Enable Application Identity service (AppIDSvc)
$Service = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($Service) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    if ($Service.Status -ne "Running") {
        Start-Service -Name AppIDSvc
    }
    Write-Host "[+] Application Identity service configured to start automatically and is running." -ForegroundColor Green
} else {
    Write-Error "Application Identity service (AppIDSvc) is not present on this system."
}

# 2. Configure local AppLocker policy XML content
$AppLockerXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e1e-453f-b3a5-bc4f4a38674d" Name="(Default Rule) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-6d8f-4ad9-acbc-467b78a7f7b4" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c1de5732e9" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="1e8fa8b3-3a5e-4c7a-9cb8-b223ff9db261" Name="Block User Writeable Temp" Description="Block execution from Temp folder to prevent bypasses." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="2e8fa8b3-3a5e-4c7a-9cb8-b223ff9db262" Name="Block User Writeable Tasks" Description="Block execution from Tasks folder to prevent bypasses." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="3e8fa8b3-3a5e-4c7a-9cb8-b223ff9db263" Name="Block User Writeable spool color" Description="Block execution from spool color folder." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\System32\spool\drivers\color\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="4e8fa8b3-3a5e-4c7a-9cb8-b223ff9db264" Name="Block Msbuild" Description="Block msbuild.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\msbuild.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="5e8fa8b3-3a5e-4c7a-9cb8-b223ff9db265" Name="Block Installutil" Description="Block installutil.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\installutil.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="6e8fa8b3-3a5e-4c7a-9cb8-b223ff9db266" Name="Block Mshta" Description="Block mshta.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\mshta.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="7e8fa8b3-3a5e-4c7a-9cb8-b223ff9db267" Name="Block Regasm" Description="Block regasm.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\regasm.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="8e8fa8b3-3a5e-4c7a-9cb8-b223ff9db268" Name="Block Regsvcs" Description="Block regsvcs.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\regsvcs.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="ae8fa8b3-3a5e-4c7a-9cb8-b223ff9db269" Name="Block Regsvr32" Description="Block regsvr32.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\regsvr32.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="be8fa8b3-3a5e-4c7a-9cb8-b223ff9db270" Name="Block Rundll32" Description="Block rundll32.exe to prevent bypass." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*\rundll32.exe" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="5b8fa8b3-3a5e-4c7a-9cb8-b223ff9db271" Name="(Default Rule) All Windows Installer files in Program Files" Description="Allows everyone to run Windows Installer files in Program Files." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="6b8fa8b3-3a5e-4c7a-9cb8-b223ff9db272" Name="(Default Rule) All Windows Installer files in Windows" Description="Allows everyone to run Windows Installer files in Windows." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="7b8fa8b3-3a5e-4c7a-9cb8-b223ff9db273" Name="(Default Rule) All Windows Installer files" Description="Allows administrators to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="1c8fa8b3-3a5e-4c7a-9cb8-b223ff9db274" Name="(Default Rule) All scripts located in the Program Files folder" Description="Allows everyone to run scripts in Program Files." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="2c8fa8b3-3a5e-4c7a-9cb8-b223ff9db275" Name="(Default Rule) All scripts located in the Windows folder" Description="Allows everyone to run scripts in Windows." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="3c8fa8b3-3a5e-4c7a-9cb8-b223ff9db276" Name="(Default Rule) All scripts" Description="Allows administrators to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="4c8fa8b3-3a5e-4c7a-9cb8-b223ff9db277" Name="Block scripts in Temp" Description="Block script execution from Temp." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="5c8fa8b3-3a5e-4c7a-9cb8-b223ff9db278" Name="Block scripts in Tasks" Description="Block script execution from Tasks." UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="1d8fa8b3-3a5e-4c7a-9cb8-b223ff9db279" Name="(Default Rule) All signed packaged apps" Description="Allows everyone to run signed packaged apps." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# Write the temporary XML and import it
$TempPath = Join-Path -Path $env:TEMP -ChildPath "AppLockerDCPolicy.xml"
$AppLockerXml | Out-File -FilePath $TempPath -Encoding UTF8 -Force

try {
    Import-Module AppLocker -ErrorAction Stop
    Set-AppLockerPolicy -XmlPolicy $TempPath -ErrorAction Stop
    Write-Host "[+] Local AppLocker policy imported and enforced successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import AppLocker policy: $($_.Exception.Message)"
} finally {
    if (Test-Path $TempPath) {
        Remove-Item -Path $TempPath -Force
    }
}

# 3. Disable NTVDM (16-bit compatibility) via Registry
$NtvdmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
if (-not (Test-Path $NtvdmPath)) {
    New-Item -Path $NtvdmPath -Force | Out-Null
}
Set-ItemProperty -Path $NtvdmPath -Name "Prevent16BitApp" -Value 1 -Type DWord
Write-Host "[+] 16-bit NTVDM compatibility disabled in registry." -ForegroundColor Green
```

*To audit the Application Identity service and AppLocker registry configuration:*
[Download Script: Get-AppLockerDCStatus.ps1](audit_scripts/Get-AppLockerDCStatus.ps1)

```powershell
# Get-AppLockerDCStatus.ps1
# Description: Checks the configuration state of the AppIDSvc service and AppLocker registry paths.

Write-Host "--- Auditing AppLocker Configuration ---" -ForegroundColor Cyan

# 1. Audit service state
$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppIDSvc) {
    $SvcColor = if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") { "Green" } else { "Yellow" }
    Write-Host "    - Application Identity Service: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType) (Expected: Running | Automatic)" -ForegroundColor $SvcColor
} else {
    Write-Host "    - Application Identity Service: NOT INSTALLED" -ForegroundColor Red
}

# 2. Audit enforcement registry settings
$SrpPath = "HKLM:\Software\Policies\Microsoft\Windows\SrpV2"
$Collections = @("Exe", "Msi", "Script", "Appx")

if (Test-Path $SrpPath) {
    foreach ($Col in $Collections) {
        $ColPath = "$SrpPath\$Col"
        if (Test-Path $ColPath) {
            $Val = Get-ItemProperty -Path $ColPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
            if ($null -ne $Val) {
                $Mode = if ($Val.EnforcementMode -eq 1) { "Enforced" } else { "Audit Only" }
                $Color = if ($Val.EnforcementMode -eq 1) { "Green" } else { "Yellow" }
                Write-Host "    - Collection $Col Enforcement: $Mode (Value: $($Val.EnforcementMode))" -ForegroundColor $Color
            } else {
                Write-Host "    - Collection $Col Enforcement: NOT CONFIGURED" -ForegroundColor Red
            }
        } else {
            Write-Host "    - Collection $Col Path: NOT FOUND" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[-] AppLocker registry base path (SrpV2) not found. Policy is not deployed." -ForegroundColor Red
}

# 3. Audit NTVDM Disable Status
$NtvdmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
if (Test-Path $NtvdmPath) {
    $AppCompatVal = Get-ItemProperty -Path $NtvdmPath -Name "Prevent16BitApp" -ErrorAction SilentlyContinue
    if ($null -ne $AppCompatVal -and $AppCompatVal.Prevent16BitApp -eq 1) {
        Write-Host "    - NTVDM (16-bit AppCompat): Disabled (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - NTVDM (16-bit AppCompat): Enabled or Not Configured (Expected: Disabled)" -ForegroundColor Yellow
    }
} else {
    Write-Host "    - NTVDM (16-bit AppCompat): Not Configured (Expected: Disabled)" -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations Section 3.1.2 (System hardening and configuration baseline controls), DAT-NT-13 Note Technique (R8, R10, R15, R16, R20)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9 (Application Control Policies / AppLocker)
* **Microsoft Security Baseline Focus**: Domain Controller Security baseline - AppLocker configurations
* **Ultimate AppLocker Bypass List**: Generic & Verified AppLocker Bypasses
