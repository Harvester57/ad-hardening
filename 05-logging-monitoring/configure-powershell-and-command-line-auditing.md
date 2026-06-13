# [REQ-LOG-002] Configure PowerShell and Command-Line Auditing

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Process Command-Line**: `Computer Configuration\Policies\Administrative Templates\System\Audit Process Creation\Include command line in process creation events`
    - Registry: `HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Policy` (Value: 1)
  * **PowerShell Script Block Logging**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Script Block Logging`
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` (Value: 1)
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging` (Value: 0)
  * **PowerShell Module Logging**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Module Logging`
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging` (Value: 1)
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\*` (Value: "*")
  * **PowerShell Transcription**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Transcription`
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting` (Value: 1)
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader` (Value: 1)
    - Registry: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory` (Value: "C:\ProgramData\PowerShellTranscripts")

---

## Rationale
Adversaries make extensive use of built-in system tools (LOLBins) and PowerShell script execution to perform reconnaissance, privilege escalation, and lateral movement. Because PowerShell code can be dynamically obfuscated or executed directly in memory without writing to disk, traditional file-based detection mechanisms are easily bypassed.

Enforcing advanced execution logging mitigates these threat vectors:
1. **Command Line Auditing**: Injecting command-line arguments into Security Event ID 4688 allows defenders to see parameters, file paths, and encoded arguments used during process execution.
2. **Script Block Logging**: Captures the full content of code blocks executed by PowerShell (Event ID 4104), logging the actual code after decryption and de-obfuscation at runtime.
3. **Module Logging**: Logs pipeline execution details and loaded modules (Event ID 4103) to map tool usage.
4. **Hardened Transcription**: Records all input commands and console outputs to local text transcripts. By restricting folder access permissions, users are blocked from reading previously typed commands (which may contain sensitive arguments, tokens, or credentials), while still allowing the system to log their actions.

---

## Legacy Impact & Compatibility
* **Disk Space Utilization**: Transcription files and verbose script block logs consume disk storage and create disk I/O. System administrators must ensure that the transcript destination directory is regularly audited, and that logs are forwarded to a SIEM and purged to prevent disk exhaustion.
* **Sensitive Telemetry**: Transcripts can accidentally log sensitive data like passwords typed in cleartext or API keys passed on the command line. Securing the transcription folder using strict NTFS ACLs is mandatory.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Configure Process Command-Line Logging
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to target systems (e.g., `GPO_Hardening_Logging_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Audit Process Creation`
4. Configure the setting:
   * **Policy**: `Include command line in process creation events`
   * **Setting**: `Enabled`

#### 2. Configure PowerShell Audit Settings
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell`
2. Configure **Script Block Logging**:
   * **Policy**: `Turn on PowerShell Script Block Logging`
   * **Setting**: `Enabled` (Ensure **Log script block invocation start / stop events** is **unchecked** / disabled to prevent operational log flooding)
3. Configure **Module Logging**:
   * **Policy**: `Turn on PowerShell Module Logging`
   * **Setting**: `Enabled` -> Click **Show...** -> Add `*` under Value.
4. Configure **PowerShell Transcription**:
   * **Policy**: `Turn on PowerShell Transcription`
   * **Setting**: `Enabled`
   * **Transcript output directory**: `C:\ProgramData\PowerShellTranscripts` (Ensure this is a local path)
   * **Include invocation headers**: Checked

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure command line process creation, PowerShell logging registry keys, and create the hardened transcript directory with write-only NTFS permissions.

[Download Script: Set-PowerShellAuditing.ps1](implementation_scripts/Set-PowerShellAuditing.ps1)

```powershell
# Set-PowerShellAuditing.ps1
# Configures command line auditing, PowerShell logging, transcription, and hardens folder ACLs.

Write-Host "--- Applying PowerShell & Command Line Auditing Remediation ---" -ForegroundColor Cyan

# 1. Enable Process Creation Command-Line Auditing
Write-Host "[+] Configuring Command Line Process Auditing..." -ForegroundColor Gray
$ProcAuditReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $ProcAuditReg)) {
    New-Item -Path $ProcAuditReg -Force | Out-Null
}
Set-ItemProperty -Path $ProcAuditReg -Name "ProcessCreationIncludeCmdLine_Policy" -Value 1 -Type DWord
Write-Host "    Command line process auditing enabled." -ForegroundColor Green

# 2. Configure PowerShell Script Block Logging
Write-Host "[+] Configuring PowerShell Script Block Logging..." -ForegroundColor Gray
$ScriptBlockReg = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $ScriptBlockReg)) {
    New-Item -Path $ScriptBlockReg -Force | Out-Null
}
Set-ItemProperty -Path $ScriptBlockReg -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $ScriptBlockReg -Name "EnableScriptBlockInvocationLogging" -Value 0 -Type DWord
Write-Host "    PowerShell Script Block Logging enabled and invocation start/stop logging disabled." -ForegroundColor Green

# 3. Configure PowerShell Module Logging
Write-Host "[+] Configuring PowerShell Module Logging..." -ForegroundColor Gray
$ModuleReg = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $ModuleReg)) {
    New-Item -Path $ModuleReg -Force | Out-Null
}
Set-ItemProperty -Path $ModuleReg -Name "EnableModuleLogging" -Value 1 -Type DWord

$ModuleNamesReg = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (-not (Test-Path $ModuleNamesReg)) {
    New-Item -Path $ModuleNamesReg -Force | Out-Null
}
Set-ItemProperty -Path $ModuleNamesReg -Name "*" -Value "*" -Type String
Write-Host "    PowerShell Module Logging enabled for all modules." -ForegroundColor Green

# 4. Configure PowerShell Transcription
Write-Host "[+] Configuring PowerShell Transcription Registry settings..." -ForegroundColor Gray
$TransReg = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $TransReg)) {
    New-Item -Path $TransReg -Force | Out-Null
}
$TranscriptPath = "C:\ProgramData\PowerShellTranscripts"
Set-ItemProperty -Path $TransReg -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $TransReg -Name "EnableInvocationHeader" -Value 1 -Type DWord
Set-ItemProperty -Path $TransReg -Name "OutputDirectory" -Value $TranscriptPath -Type String
Write-Host "    PowerShell Transcription registry keys configured." -ForegroundColor Green

# 5. Create and Harden PowerShell Transcript Folder
Write-Host "[+] Setting up hardened NTFS permissions on $($TranscriptPath)..." -ForegroundColor Gray
if (-not (Test-Path $TranscriptPath)) {
    New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
}

# Fetch ACL and disable inheritance, copying existing rules
$Acl = Get-Acl -Path $TranscriptPath
$Acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $TranscriptPath -AclObject $Acl

# Refresh ACL and remove user/authenticated user permissions
$Acl = Get-Acl -Path $TranscriptPath
$Rules = $Acl.Access
foreach ($Rule in $Rules) {
    $Identity = $Rule.IdentityReference.Value
    if ($Identity -like "*Users" -or $Identity -like "*Authenticated Users" -or $Identity -like "*Everyone") {
        $Acl.RemoveAccessRule($Rule) | Out-Null
    }
}

# Define write-only permissions for Authenticated Users
# CreateFiles/AppendData allows logging, while missing ListDirectory/ReadData blocks viewing transcripts.
$WriteRights = [System.Security.AccessControl.FileSystemRights]("CreateFiles, AppendData, ReadAttributes, WriteAttributes")
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]("ContainerInherit, ObjectInherit")
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
$AccessType = [System.Security.AccessControl.AccessControlType]::Allow

$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\Authenticated Users", $WriteRights, $InheritanceFlags, $PropagationFlags, $AccessType)
$Acl.AddAccessRule($AccessRule)
Set-Acl -Path $TranscriptPath -AclObject $Acl
Write-Host "    Hardened NTFS permissions applied to $($TranscriptPath) successfully." -ForegroundColor Green
```

*To verify the settings have been applied:*

[Download Script: Test-PowerShellAuditing.ps1](audit_scripts/Test-PowerShellAuditing.ps1)

```powershell
# Test-PowerShellAuditing.ps1
# Audits command line process creation, PowerShell logging, and transcript folder permissions.

Write-Host "--- Auditing PowerShell & Command Line Auditing ---" -ForegroundColor Cyan

# 1. Audit Process Command-Line Logging
$ProcPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$CmdLineVal = Get-ItemProperty -Path $ProcPath -Name "ProcessCreationIncludeCmdLine_Policy" -ErrorAction SilentlyContinue
$CmdSetting = 0
if ($CmdLineVal) {
    $CmdSetting = $CmdLineVal.ProcessCreationIncludeCmdLine_Policy
}
$CmdColor = "Red"
if ($CmdSetting -eq 1) {
    $CmdColor = "Green"
}
Write-Host "    - Command Line Process Auditing: $($CmdSetting) (Required = 1)" -ForegroundColor $CmdColor

# 2. Audit Script Block Logging
$SBPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$SBVal = Get-ItemProperty -Path $SBPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
$SBSetting = 0
if ($SBVal) {
    $SBSetting = $SBVal.EnableScriptBlockLogging
}
$SBColor = "Red"
if ($SBSetting -eq 1) {
    $SBColor = "Green"
}
Write-Host "    - PowerShell Script Block Logging: $($SBSetting) (Required = 1)" -ForegroundColor $SBColor

$SBInvVal = Get-ItemProperty -Path $SBPath -Name "EnableScriptBlockInvocationLogging" -ErrorAction SilentlyContinue
$SBInvSetting = 0
if ($SBInvVal) {
    $SBInvSetting = $SBInvVal.EnableScriptBlockInvocationLogging
}
$SBInvColor = "Red"
if ($SBInvSetting -eq 0) {
    $SBInvColor = "Green"
}
Write-Host "    - PowerShell Script Block Invocation Logging (Start/Stop): $($SBInvSetting) (Required = 0)" -ForegroundColor $SBInvColor

# 3. Audit Module Logging
$ModPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$ModVal = Get-ItemProperty -Path $ModPath -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
$ModSetting = 0
if ($ModVal) {
    $ModSetting = $ModVal.EnableModuleLogging
}
$ModColor = "Red"
if ($ModSetting -eq 1) {
    $ModColor = "Green"
}
Write-Host "    - PowerShell Module Logging: $($ModSetting) (Required = 1)" -ForegroundColor $ModColor

# 4. Audit Transcription Setup
$TransPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
$TransVal = Get-ItemProperty -Path $TransPath -Name "EnableTranscripting" -ErrorAction SilentlyContinue
$TransSetting = 0
if ($TransVal) {
    $TransSetting = $TransVal.EnableTranscripting
}
$TransColor = "Red"
if ($TransSetting -eq 1) {
    $TransColor = "Green"
}
Write-Host "    - PowerShell Transcription Enabled: $($TransSetting) (Required = 1)" -ForegroundColor $TransColor

$TransDirVal = Get-ItemProperty -Path $TransPath -Name "OutputDirectory" -ErrorAction SilentlyContinue
$TransDir = ""
if ($TransDirVal) {
    $TransDir = $TransDirVal.OutputDirectory
}
Write-Host "    - PowerShell Transcription Directory: $($TransDir)" -ForegroundColor (if ($TransDir) { "Green" } else { "Red" })

# 5. Audit Transcript Folder Security Permissions
if ($TransDir) {
    if (-not (Test-Path $TransDir)) {
        Write-Host "    - Transcription directory does not exist locally." -ForegroundColor Red
    } else {
        $Acl = Get-Acl -Path $TransDir
        $Rules = $Acl.Access
        $HasUnsafeRead = $false
        $HasWriteOnly = $false
        
        foreach ($Rule in $Rules) {
            $Identity = $Rule.IdentityReference.Value
            $Rights = $Rule.FileSystemRights
            $Type = $Rule.AccessControlType
            
            if ($Type -eq "Allow" -and ($Identity -like "*Authenticated Users" -or $Identity -like "*Users" -or $Identity -like "*Everyone")) {
                # Look for read access
                $UnsafeRights = @("ReadData", "ListDirectory", "FullControl", "Modify", "Delete", "ReadAndExecute", "Read")
                foreach ($Right in $UnsafeRights) {
                    if ($Rights.ToString() -match $Right) {
                        $HasUnsafeRead = $true
                    }
                }
                
                # Check for write-only parameters
                if ($Rights.ToString() -match "CreateFiles" -and $Rights.ToString() -match "AppendData" -and -not ($Rights.ToString() -match "ReadData")) {
                    $HasWriteOnly = $true
                }
            }
        }
        
        $AclColor = "Red"
        if ($HasWriteOnly -and -not $HasUnsafeRead) {
            $AclColor = "Green"
        }
        Write-Host "    - Transcript Folder Security: WriteOnly=$($HasWriteOnly), UnsafeReadAccess=$($HasUnsafeRead)" -ForegroundColor $AclColor
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R50 (PowerShell logging configuration)
* **CIS Benchmark**: CIS Windows Server 2016 Benchmark v2.0.0 - Section 18.8 (PowerShell Logging)
* **Microsoft Security Baseline Focus**: Windows Administrative Templates (PowerShell Script Block Logging / Transcription)
