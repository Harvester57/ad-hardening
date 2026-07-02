# New-SYSVOLHoneypot.ps1
# Description: Configures a decoy Group Policy Preferences XML file in SYSVOL with Everyone:Deny read permissions and file access failure auditing.
# Target Engine: Windows PowerShell 5.1

Write-Host "Applying hardening requirement: Configure SYSVOL Decoy XML Honeypot..." -ForegroundColor Cyan

# 1. Retrieve local SYSVOL path
$SysvolReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "Sysvol" -ErrorAction SilentlyContinue
if (-not $SysvolReg) {
    Write-Host "[*] SYSVOL registry path not found. Checking standard share path..." -ForegroundColor Yellow
    $SysvolPath = "C:\Windows\SYSVOL\sysvol"
} else {
    $SysvolPath = $SysvolReg.Sysvol
}

if (-not (Test-Path -Path $SysvolPath)) {
    Write-Host "[-] SYSVOL folder not found at path: $SysvolPath. Honeypot cannot be deployed." -ForegroundColor Red
    exit 1
}

# Resolve the active Policies folder path
$PoliciesPath = Get-ChildItem -Path $SysvolPath -Directory | ForEach-Object {
    Join-Path $_.FullName "Policies"
} | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $PoliciesPath) {
    Write-Host "[-] GPO Policies folder not found under SYSVOL: $SysvolPath" -ForegroundColor Red
    exit 1
}

# 2. Check if a decoy is already registered
$RegPath = "HKLM:\SOFTWARE\ADHardening\SYSVOLHoneypot"
$ExistingGuid = $null
$ExistingPath = $null

if (Test-Path $RegPath) {
    $ExistingGuid = (Get-ItemProperty -Path $RegPath -Name "DecoyGuid" -ErrorAction SilentlyContinue).DecoyGuid
    $ExistingPath = (Get-ItemProperty -Path $RegPath -Name "DecoyPath" -ErrorAction SilentlyContinue).DecoyPath
}

# If it exists, verify it
$DeployNew = $true
if ($ExistingGuid -and $ExistingPath -and (Test-Path $ExistingPath)) {
    Write-Host "[*] Decoy GPO already registered in registry with GUID: $ExistingGuid" -ForegroundColor Yellow
    $DeployNew = $false
}

if ($DeployNew) {
    # Generate a new random GUID
    $Guid = [guid]::NewGuid().ToString("B").ToUpper()
    $DecoyGpoPath = Join-Path $PoliciesPath $Guid
    $DecoyGroupsPath = Join-Path $DecoyGpoPath "Machine\Preferences\Groups"
    $DecoyXmlPath = Join-Path $DecoyGroupsPath "Groups.xml"

    Write-Host "[*] Deploying new decoy GPO folder at: $DecoyGpoPath" -ForegroundColor White
    New-Item -ItemType Directory -Path $DecoyGroupsPath -Force | Out-Null

    # Create dummy XML file with decoy cpassword content
    $DecoyXmlContent = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{312F64FA-EB90-4b2e-A6AE-E8C1FCDD4A2C}">
  <User clsid="{15C200C5-AE9F-4a18-A372-FD51206104C1}" name="BuiltinAdminDecoy" image="0" changed="2026-07-02 20:56:00" uid="{B6396E70-2EA1-46B4-9F6D-E5D3AD3CD2BE}">
    <Properties action="U" newName="LocalAdministrator" changeLogon="0" noChange="1" neverExpires="1" disabled="0" cpassword="j1Uyj/k7S8248c8j838jjSjjSj2jJ29" description="Decoy local admin account for automation services"/>
  </User>
</Groups>
'@
    Set-Content -Path $DecoyXmlPath -Value $DecoyXmlContent -Force | Out-Null
    Write-Host "[+] Decoy GPP Groups.xml created." -ForegroundColor Green

    # Save to Registry
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RegPath -Name "DecoyGuid" -Value $Guid -Type String
    Set-ItemProperty -Path $RegPath -Name "DecoyPath" -Value $DecoyXmlPath -Type String
    Write-Host "[+] Registered Decoy Guid: $Guid in HKLM:\SOFTWARE\ADHardening\SYSVOLHoneypot" -ForegroundColor Gray
} else {
    $DecoyXmlPath = $ExistingPath
}

# 3. Configure permissions: Deny Everyone Read access
Write-Host "[*] Enforcing Deny Read/Execute permissions for Everyone on decoy file..." -ForegroundColor White
$Acl = Get-Acl -Path $DecoyXmlPath

# Check if Deny rule for Everyone already exists to avoid duplication
$HasDenyRule = $false
foreach ($rule in $Acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])) {
    if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
        $HasDenyRule = $true
        break
    }
}

if (-not $HasDenyRule) {
    $Identity = "Everyone"
    $Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Read
    $Inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
    $Type = [System.Security.AccessControl.AccessControlType]::Deny

    $DenyRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Rights, $Inheritance, $Propagation, $Type)
    $Acl.AddAccessRule($DenyRule)
    Set-Acl -Path $DecoyXmlPath -AclObject $Acl
    Write-Host "[+] Applied Deny Everyone rule successfully." -ForegroundColor Green
} else {
    Write-Host "[*] Deny Everyone rule is already present." -ForegroundColor Yellow
}

# 4. Configure Object Auditing for Failure (SACL)
Write-Host "[*] Configuring Failure Audit rule for Everyone on decoy file..." -ForegroundColor White

# To set SACL, we must load the ACL with audit rules
$AclAudit = Get-Acl -Path $DecoyXmlPath -Audit

$HasAuditRule = $false
foreach ($rule in $AclAudit.GetAuditRules($true, $false, [System.Security.Principal.NTAccount])) {
    if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.AuditFlags -eq [System.Security.AccessControl.AuditFlags]::Failure) {
        $HasAuditRule = $true
        break
    }
}

if (-not $HasAuditRule) {
    $AuditIdentity = "Everyone"
    $AuditRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Read
    $AuditInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $AuditPropagation = [System.Security.AccessControl.PropagationFlags]::None
    $AuditFlags = [System.Security.AccessControl.AuditFlags]::Failure

    $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditIdentity, $AuditRights, $AuditInheritance, $AuditPropagation, $AuditFlags)
    $AclAudit.AddAuditRule($AuditRule)
    
    # Set the ACL with audit rules back to the file
    Set-Acl -Path $DecoyXmlPath -AclObject $AclAudit
    Write-Host "[+] Applied Failure Audit rule successfully." -ForegroundColor Green
} else {
    Write-Host "[*] Failure Audit rule is already present." -ForegroundColor Yellow
}

Write-Host "SYSVOL Decoy XML Honeypot configuration completed successfully." -ForegroundColor Green
