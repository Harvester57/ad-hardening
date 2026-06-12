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
Write-Host "    PowerShell Script Block Logging enabled." -ForegroundColor Green

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
