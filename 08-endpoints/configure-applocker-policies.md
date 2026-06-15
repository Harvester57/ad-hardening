# Hardening Requirement: Configure AppLocker Policies for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (and above), Windows 11 Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker

---

## Rationale
Endpoints and general member servers are the most common entry points for malware, ransomware, and administrative account compromise. Standard users running with non-administrative accounts can download and execute malicious executables or scripts in writeable directories (like `%TEMP%` or `%USERPROFILE%`) to bypass traditional signature-based antivirus solutions.

Enforcing strict application control via AppLocker on endpoints ensures that:
1. **Malware Prevention**: Standard users are blocked from executing unauthorized binaries and installers.
2. **Defends Against AppLocker Bypasses**: Abusing trusted, signed Microsoft binaries (such as `msbuild.exe`, `installutil.exe`, `regasm.exe`, `regsvcs.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`) allows attackers to execute arbitrary code bypassing default AppLocker rules. This control blocks these "Living off the Land" binaries (LOLBins) and prevents execution from user-writeable paths under `%WINDIR%` (such as `Tasks`, `Temp`, `tracing`, `spool\drivers\color`, etc.).
3. **Restricts Interpreted Codes**: Block unauthorized execution of scripts (PowerShell, VBScript, Batch) from writeable locations.
4. **Defense-in-Depth**: Limits the lateral movement of adversaries who pivot from one compromised endpoint to another.

---

## Legacy Impact & Compatibility
* **Authorized Software Only**: Users will be unable to run arbitrary executables, portable apps, or custom scripts. Standard deployment mechanisms (like SCCM, Microsoft Intune, or active software deployment tools) must be used, or explicit rules must be maintained.
* **Developer & Power User Impact**: Developers and power users who need to compile code locally or run custom utilities will be impacted. Dedicated whitelists or exceptions based on certificate publisher must be implemented.
* **Audit Mode Deployment**: Due to the high potential for system disruption, the policy must first be deployed in **Audit Only** mode for a validation period to collect logs and verify that no legitimate applications are blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the workstations/member servers Organizational Unit (OU) (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Double-click **Application Identity**.
5. Select **Define this policy setting** and configure the startup mode to **Automatic**.
6. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
7. Configure AppLocker Enforcement:
   * Right-click **AppLocker** and select **Properties**.
   * On the **Enforcement** tab, check **Configured** under:
     * **Executable rules** -> Select **Enforce rules** (or **Audit only** for testing)
     * **Windows Installer rules** -> Select **Enforce rules**
     * **Script rules** -> Select **Enforce rules**
     * **Packaged app rules** -> Select **Enforce rules**
8. Right-click **Executable Rules** and select **Create Default Rules** (this permits Windows files and program files).
9. Delete the default rule allowing "Everyone" to run files in all locations, and replace it with a rule allowing only authorized administrative groups (e.g., `Domain Admins`, `Local Administrators`) to run binaries outside the default system locations.
10. Per **ANSSI R2** recommendation, do not create standalone Deny rules. Instead, configure the following path **Exceptions** on the default Allow rule for the Windows folder:
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
11. Repeat the process for **Script Rules** by creating default rules and adding exceptions to the `%WINDIR%\*` Allow rule for script execution from user-writeable paths (such as `%WINDIR%\Temp\*` and `%WINDIR%\Tasks\*`).
12. Disable NTVDM (16-bit application support) to prevent AppLocker bypasses via 16-bit binaries:
   * Navigate to: `Computer Configuration\Administrative Templates\System\16-bit Application Compatibility`
   * Configure **Prevent access to 16-bit applications** to **Enabled**.
13. Link the GPO to the Endpoints Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the Application Identity service (`AppIDSvc`) and import the robust AppLocker policy locally.

[Download Script: Configure-EndpointAppLocker.ps1](implementation_scripts/Configure-EndpointAppLocker.ps1)

```powershell
# Configure-EndpointAppLocker.ps1
# Description: Configures the Application Identity service (AppIDSvc) to start automatically and imports a robust AppLocker XML policy.

Write-Host "Applying AppLocker Identity service hardening..." -ForegroundColor Cyan

# 1. Enable Application Identity service (AppIDSvc)
$AppLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppLockerService) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "[+] Application Identity Service (AppIDSvc) set to Automatic and started." -ForegroundColor Green
} else {
    Write-Warning "[-] Application Identity Service not found on this machine."
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
$TempPath = Join-Path -Path $env:TEMP -ChildPath "AppLockerEndpointPolicy.xml"
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

*To verify the AppLocker service status:*

[Download Script: Test-EndpointAppLockerStatus.ps1](audit_scripts/Test-EndpointAppLockerStatus.ps1)

```powershell
# Test-EndpointAppLockerStatus.ps1
# Description: Checks the current configuration and operational status of the Application Identity service.

Write-Host "--- Auditing AppLocker Service Status ---" -ForegroundColor Cyan

# 1. Audit service state
$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($AppIDSvc) {
    if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") {
        Write-Host "    - AppLocker Service Status: Running | Startup: Automatic (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: AppLocker Service Status: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType) (Should be Running/Automatic)" -ForegroundColor Red
    }
} else {
    Write-Host "    - VULNERABLE: Application Identity Service (AppIDSvc) is not installed." -ForegroundColor Red
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
* **ANSSI AD Hardening Guide**: DAT-NT-13 Note Technique (R2, R8, R10, R15, R16, R20)
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.9 (AppLocker Application Control)
* **Microsoft Security Baselines**: AppLocker deployment guidance for client environments.
* **Ultimate AppLocker Bypass List**: Generic & Verified AppLocker Bypasses
