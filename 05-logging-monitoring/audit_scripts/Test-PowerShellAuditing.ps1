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
