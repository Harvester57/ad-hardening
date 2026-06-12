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
$TempPath = Join-Path -Path $env:TEMP -ChildPath "AppLockerEndpointPolicy.xml"
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
