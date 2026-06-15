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

#### 3. Create Default and Exception Rules
1. Expand **AppLocker** and select **Executable Rules**.
2. Right-click **Executable Rules** and select **Create Default Rules** (allows all files in Windows and Program Files directories, and allows local Administrators to run all files).
3. Per **ANSSI R2** recommendation, do not create standalone Deny rules. Instead, configure the following path **Exceptions** on the default Allow rule for the Windows folder:
   * Right-click the rule `(Default Rule) All files located in the Windows folder` and select **Properties**.
   * On the **Exceptions** tab, add path exceptions for writeable directories under `%WINDIR%`:
     * `%WINDIR%\Tasks\*`
     * `%WINDIR%\Temp\*`
     * `%WINDIR%\tracing\*`
     * `%WINDIR%\System32\spool\drivers\color\*`
     * `%WINDIR%\System32\Tasks\Microsoft\Windows\SyncCenter\*`
     * `%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*`
   * On the same **Exceptions** tab, add path exceptions for the following bypass binaries (LOLBins):
     * `*\msbuild.exe`
     * `*\installutil.exe`
     * `*\mshta.exe`
     * `*\regasm.exe`
     * `*\regsvcs.exe`
     * `*\regsvr32.exe`
     * `*\rundll32.exe`
     * `*\bginfo.exe`
     * `*\cdb.exe`
     * `*\cmstp.exe`
     * `*\control.exe`
     * `*\csi.exe`
     * `*\dfsvc.exe`
     * `*\dnx.exe`
     * `*\fsi.exe`
     * `*\ie4unit.exe`
     * `*\ieexec.exe`
     * `*\infdefaultinstall.exe`
     * `*\mavinject.exe`
     * `*\msdeploy.exe`
     * `*\msdt.exe`
     * `*\msxsl.exe`
     * `*\odbcconf.exe`
     * `*\presentationhost.exe`
     * `*\rcsi.exe`
     * `*\rsi.exe`
     * `*\runscripthelper.exe`
     * `*\te.exe`
     * `*\tracker.exe`
     * `*\xwizard.exe`
4. Repeat the process for **Script Rules** by creating default rules and adding exceptions to the `%WINDIR%\*` Allow rule for script execution from user-writeable paths (such as `%WINDIR%\Temp\*` and `%WINDIR%\Tasks\*`).
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
      <Exceptions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
        <FilePathCondition Path="%WINDIR%\System32\spool\drivers\color\*" />
        <FilePathCondition Path="*\msbuild.exe" />
        <FilePathCondition Path="*\installutil.exe" />
        <FilePathCondition Path="*\mshta.exe" />
        <FilePathCondition Path="*\regasm.exe" />
        <FilePathCondition Path="*\regsvcs.exe" />
        <FilePathCondition Path="*\regsvr32.exe" />
        <FilePathCondition Path="*\rundll32.exe" />
      </Exceptions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c1de5732e9" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
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
      <Exceptions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Exceptions>
    </FilePathRule>
    <FilePathRule Id="3c8fa8b3-3a5e-4c7a-9cb8-b223ff9db276" Name="(Default Rule) All scripts" Description="Allows administrators to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
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

# 3. Validate policy using Test-AppLockerPolicy before importing
try {
    Import-Module AppLocker -ErrorAction Stop
} catch {
    Write-Error "AppLocker module is not available on this system. Cannot configure or validate policy."
    if (Test-Path $TempPath) {
        Remove-Item -Path $TempPath -Force
    }
    return
}

$TestPaths = @(
    # Expected: Allowed
    "$env:windir\System32\cmd.exe",
    "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe",
    # Expected: DeniedByDefault or ExplicitlyDenied (since it is an exception to an Allow rule)
    "$env:USERPROFILE\Downloads\tool.exe",
    "$env:windir\Temp\malware.exe",
    "$env:windir\Tasks\evil.exe",
    "$env:windir\System32\msbuild.exe"
)

$ValidationFailed = $false
try {
    $TestResults = Test-AppLockerPolicy -XmlPolicy $TempPath -Path $TestPaths -User Everyone -ErrorAction Stop
    $ExpectedAllow = @(
        "$env:windir\System32\cmd.exe",
        "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    $ExpectedDeny = @(
        "$env:USERPROFILE\Downloads\tool.exe",
        "$env:windir\Temp\malware.exe",
        "$env:windir\Tasks\evil.exe",
        "$env:windir\System32\msbuild.exe"
    )

    foreach ($Result in $TestResults) {
        $Path = $Result.FilePath
        $Decision = $Result.PolicyDecision
        if ($ExpectedAllow -contains $Path) {
            if ($Decision -ne "Allowed") {
                Write-Warning "[VALIDATION FAIL] Expected Allow for: $Path (got: $Decision)"
                $ValidationFailed = $true
            }
        }
        if ($ExpectedDeny -contains $Path) {
            if ($Decision -eq "Allowed") {
                Write-Warning "[VALIDATION FAIL] Expected Deny/Not Allowed for: $Path (got: $Decision)"
                $ValidationFailed = $true
            }
        }
    }
} catch {
    Write-Warning "Could not perform policy validation tests: $($_.Exception.Message)"
    $ValidationFailed = $true
}

if ($ValidationFailed) {
    Write-Error "AppLocker policy validation failed. Policy was NOT imported."
    if (Test-Path $TempPath) {
        Remove-Item -Path $TempPath -Force
    }
    return
}

Write-Host "[+] AppLocker policy validation passed. Proceeding with import." -ForegroundColor Green

# 4. Import the validated AppLocker policy
try {
    Set-AppLockerPolicy -XmlPolicy $TempPath -ErrorAction Stop
    Write-Host "[+] Local AppLocker policy imported and enforced successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import AppLocker policy: $($_.Exception.Message)"
} finally {
    if (Test-Path $TempPath) {
        Remove-Item -Path $TempPath -Force
    }
}

# 5. Disable NTVDM (16-bit compatibility) via Registry
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
* **ANSSI AD Hardening Guide**: Recommendations Section 3.1.2 (System hardening and configuration baseline controls), DAT-NT-13 Note Technique (R2, R8, R10, R15, R16, R20)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9 (Application Control Policies / AppLocker)
* **Microsoft Security Baseline Focus**: Domain Controller Security baseline - AppLocker configurations
* **Ultimate AppLocker Bypass List**: Generic & Verified AppLocker Bypasses
