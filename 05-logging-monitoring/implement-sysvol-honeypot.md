# [REQ-LOG-006] Configure SYSVOL Decoy XML Honeypot

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: File System Auditing (Decoy file path) and Advanced Security Audit Policies (Object Access -> Audit File System)

---

## Rationale
Adversaries seeking to elevate privileges within an Active Directory domain frequently scan the `SYSVOL` share for files containing legacy Group Policy Preference (GPP) credentials (specifically searching for the `cpassword` attribute in XML files) or startup/login scripts. This discovery scanning is often automated using script search commands (e.g., `findstr /S cpassword`) or administrative diagnostic frameworks (such as PowerSploit or BloodHound).

To detect these unauthorized discovery scans, security teams can deploy a **SYSVOL Decoy XML Honeypot**. This decoy consists of a mock Group Policy folder structure containing a dummy GPP `Groups.xml` file with fake credential properties. 

Because this mock policy is not linked to any active Active Directory object, no legitimate system or user account has any reason to query or read this file. 

By applying an explicit **NTFS Deny Read** rule to the `Everyone` group on the decoy file, any attempt by an attacker to scan or read it will immediately fail and generate a high-fidelity **Access Denied** event. By configuring file failure auditing on the decoy path, Windows generates **Event ID 4656** or **4663** in the Domain Controller's Security Log. These events capture the attacker's account details and client IP address, providing a low-noise, high-fidelity alert.

---

## Legacy Impact & Compatibility
* **Auditing Dependency**: This honeypot requires Advanced File System Auditing to be enabled on the Domain Controllers. Ensure that `Audit File System` is configured for **Failure** events under the Domain Controllers' auditing policies ([REQ-LOG-001](configure-advanced-audit-policies.md)).
* **Replication Compatibility**: The decoy folder is located within the `SYSVOL` share. Since it is explicitly denied read access to `Everyone`, legacy replication components (like FRS) or standard file synchronization tools might skip it. This behavior is expected and does not impact domain services since the decoy folder is not an active GPO.

---

## Implementation Steps

### Option A: Active Directory Domain Controllers File Explorer (GUI)

To manually configure the decoy file:
1. Log on to a Domain Controller with Domain Admin privileges.
2. Navigate to the local SYSVOL policies directory (typically `C:\Windows\SYSVOL\sysvol\<domain.local>\Policies`).
3. Create a new folder with a randomly generated GUID format (e.g., `{5B7853A8-1E74-4C56-AC89-E911A34D2E5B}`).
4. Inside this folder, create the directory structure: `Machine\Preferences\Groups`.
5. Create a new file named `Groups.xml` inside `Groups` with standard XML structure and a dummy `cpassword` attribute:
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <Groups clsid="{312F64FA-EB90-4b2e-A6AE-E8C1FCDD4A2C}">
     <User clsid="{15C200C5-AE9F-4a18-A372-FD51206104C1}" name="BuiltinAdminDecoy" image="0" changed="2026-07-02 20:56:00" uid="{B6396E70-2EA1-46B4-9F6D-E5D3AD3CD2BE}">
       <Properties action="U" newName="LocalAdministrator" changeLogon="0" noChange="1" neverExpires="1" disabled="0" cpassword="j1Uyj/k7S8248c8j838jjSjjSj2jJ29" description="Decoy local admin account for automation services"/>
     </User>
   </Groups>
   ```
6. Configure the permissions to deny read access:
   - Right-click `Groups.xml` and select **Properties**.
   - Navigate to the **Security** tab and click **Advanced**.
   - Click **Add**. Set the Principal to `Everyone`. Set the Type to `Deny`. Check the permissions for `Read & execute` and `Read`. Click **OK**.
7. Configure File System Auditing on the decoy:
   - In the **Advanced Security Settings** window for `Groups.xml`, navigate to the **Auditing** tab.
   - Click **Add**. Set the Principal to `Everyone`. Set the Type to `Fail`. Check the permissions for `Read & execute` and `Read`. Click **OK**.
   - Click **Apply** and then **OK**.

---

### Option B: PowerShell & Remediation (Non-GPO / Script-based)

Use these scripts to deploy and audit the SYSVOL honeypot.

[Download Script: New-SYSVOLHoneypot.ps1](implementation_scripts/New-SYSVOLHoneypot.ps1)

```powershell
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
```

*To verify the honeypot configuration status:*

[Download Script: Get-SYSVOLHoneypotStatus.ps1](audit_scripts/Get-SYSVOLHoneypotStatus.ps1)

```powershell
# Get-SYSVOLHoneypotStatus.ps1
# Description: Checks the configuration status of the SYSVOL Decoy XML Honeypot.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing SYSVOL Decoy XML Honeypot Configuration ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$RegPath = "HKLM:\SOFTWARE\ADHardening\SYSVOLHoneypot"

if (Test-Path $RegPath) {
    $DecoyGuid = (Get-ItemProperty -Path $RegPath -Name "DecoyGuid" -ErrorAction SilentlyContinue).DecoyGuid
    $DecoyPath = (Get-ItemProperty -Path $RegPath -Name "DecoyPath" -ErrorAction SilentlyContinue).DecoyPath
    
    if (-not $DecoyGuid) {
        Write-Host "[-] Decoy GPO GUID is missing in the registry." -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    if (-not $DecoyPath) {
        Write-Host "[-] Decoy file path is missing in the registry." -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        if (-not (Test-Path $DecoyPath)) {
            Write-Host "[-] Decoy XML file does not exist at registered path: $DecoyPath" -ForegroundColor Red
            $script:Vulnerable = $true
        } else {
            Write-Host "[+] Decoy XML file found: $DecoyPath" -ForegroundColor Green
            
            # Check Deny ACL rule
            $Acl = Get-Acl -Path $DecoyPath
            $HasDenyRule = $false
            foreach ($rule in $Acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])) {
                if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                    $HasDenyRule = $true
                    break
                }
            }
            
            if ($HasDenyRule) {
                Write-Host "    - Everyone Deny Read rule: CONFIGURED" -ForegroundColor White
            } else {
                Write-Host "    - Everyone Deny Read rule: NOT CONFIGURED" -ForegroundColor Red
                $script:Vulnerable = $true
            }
            
            # Check Audit failure rule (SACL)
            $AclAudit = Get-Acl -Path $DecoyPath -Audit
            $HasAuditRule = $false
            foreach ($rule in $AclAudit.GetAuditRules($true, $false, [System.Security.Principal.NTAccount])) {
                if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.AuditFlags -eq [System.Security.AccessControl.AuditFlags]::Failure) {
                    $HasAuditRule = $true
                    break
                }
            }
            
            if ($HasAuditRule) {
                Write-Host "    - Everyone Failure Audit rule: CONFIGURED" -ForegroundColor White
            } else {
                Write-Host "    - Everyone Failure Audit rule: NOT CONFIGURED" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        }
    }
} else {
    Write-Host "[-] Decoy registry key not found under HKLM:\SOFTWARE\ADHardening\SYSVOLHoneypot" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **Sean Metcalf (ADSecurity)**: [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288) (Honeypot detection strategy)
* **ANSSI Active Directory Hardening Guide**: Recommendations on logging and security auditing policies.
* **CIS Controls**: CIS Control 8 - Audit Logs Management; CIS Control 10.5 - Configure host-based firewalls and detection sensors.
