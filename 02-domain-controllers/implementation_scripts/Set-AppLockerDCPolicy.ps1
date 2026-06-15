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
