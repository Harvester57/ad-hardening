# [REQ-ID-020] Clean Up Legacy Group Policy Preferences and SYSVOL Passwords

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: None (Domain-wide SYSVOL cleanup of legacy policy preference files and logon/startup scripts)

---

## Rationale
Historically, administrators utilized Group Policy Preferences (GPP) to automate account creation, service configurations, drive mappings, and local administrator password rotations. When credentials were saved within a GPP, the password was stored as an encrypted string under the `cpassword` attribute in XML configuration files (e.g., `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`) inside the domain-wide `SYSVOL` share.

Although Microsoft encrypted the password with AES-256, the static AES decryption key was published on MSDN. Because any authenticated user (or trust) has read access to the `SYSVOL` share, any domain user can read the preference XML files, extract the `cpassword` value, and decrypt it to obtain cleartext credentials.

Microsoft patched this vulnerability in May 2014 via **MS14-025 (KB2962486)**, which blocks the Group Policy Management Console (GPMC) from creating or updating policies that contain password fields. However, **the patch does not delete existing GPP XML files with passwords from SYSVOL**. Consequently, legacy preferences with encrypted credentials remain in the `SYSVOL` directory and continue to be a primary target for adversary credential harvesting.

Additionally, administrators historically deployed custom login or management scripts (e.g., `.vbs`, `.bat`, `.cmd`, `.ps1`) in `SYSVOL` with cleartext passwords hardcoded. These must also be identified and purged.

---

## Legacy Impact & Compatibility
* **Configuration Breakage**: Removing credentials or stripping `cpassword` properties from active Group Policy Preferences will prevent those specific objects (drives, tasks, services) from authenticating and executing. 
* **Transition Prerequisite**: Ensure that all systems requiring local administrator password rotation are migrated to Windows LAPS or Classic LAPS ([REQ-ID-002](enable-laps.md)) and all service/task authentication is migrated to Group Managed Service Accounts (gMSAs) ([REQ-ID-003](harden-service-accounts.md)) prior to cleaning up GPP passwords.

---

## Implementation Steps

### Option A: Active Directory Group Policy Management (GUI)

To manually locate and clean up credential fields:
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management server.
2. Review all active GPOs that configure Preferences (specifically under **Computer Configuration** or **User Configuration** -> **Preferences** -> **Control Panel Settings** -> **Local Users and Groups**, **Scheduled Tasks**, or **Services**).
3. If an active policy contains an account configuration with a password, recreate the policy option without specifying credentials (use LAPS or gMSA as alternatives).
4. For any GPOs no longer in use, delete them using GPMC to clean up their folders from the `SYSVOL` directory.

---

### Option B: PowerShell & Remediation (Non-GPO / Script-based)

Use these scripts to scan and automatically remediate GPP configuration files in the `SYSVOL` share.

[Download Script: Remove-GPPSYSVOLPasswords.ps1](implementation_scripts/Remove-GPPSYSVOLPasswords.ps1)

```powershell
# Remove-GPPSYSVOLPasswords.ps1
# Description: Removes cpassword attributes from Group Policy Preference XML files in SYSVOL and backs up original files.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Remediation: Cleaning Up GPP cpassword Credentials in SYSVOL ---" -ForegroundColor Cyan

# Retrieve local SYSVOL path from registry
$SysvolReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "Sysvol" -ErrorAction SilentlyContinue
if (-not $SysvolReg) {
    Write-Host "[*] SYSVOL registry path not found. Checking standard share path..." -ForegroundColor Yellow
    $SysvolPath = "C:\Windows\SYSVOL\sysvol"
} else {
    $SysvolPath = $SysvolReg.Sysvol
}

if (-not (Test-Path -Path $SysvolPath)) {
    Write-Host "[-] SYSVOL folder not found at path: $SysvolPath. Nothing to remediate." -ForegroundColor Red
    exit 0
}

# 1. Scan and remediate GPP XML files
$GppXmls = Get-ChildItem -Path $SysvolPath -Filter *.xml -Recurse -File -ErrorAction SilentlyContinue

foreach ($file in $GppXmls) {
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content.Contains("cpassword")) {
        Write-Host "[*] Found GPP file with cpassword: $($file.FullName)" -ForegroundColor Yellow
        
        # Create Backup
        $Timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $BackupPath = "$($file.FullName).bak_$Timestamp"
        Copy-Item -Path $file.FullName -Destination $BackupPath -Force -ErrorAction SilentlyContinue
        Write-Host "    [+] Created backup at: $BackupPath" -ForegroundColor Gray

        # Load XML
        [xml]$xml = New-Object System.Xml.XmlDocument
        try {
            $xml.Load($file.FullName)
            
            # Find all elements with cpassword attribute using XPath
            $Nodes = $xml.SelectNodes("//*[@cpassword]")
            if ($Nodes.Count -gt 0) {
                foreach ($Node in $Nodes) {
                    Write-Host "    [+] Stripping cpassword attribute from XML node: $($Node.Name)" -ForegroundColor White
                    $Node.RemoveAttribute("cpassword")
                    # If username exists, log it to help administrator identify what was affected
                    if ($Node.Attributes["username"]) {
                        Write-Host "    [!] Note: Node was configured for username '$($Node.Attributes["username"].Value)'" -ForegroundColor Yellow
                    }
                }
                $xml.Save($file.FullName)
                Write-Host "    [+] Successfully stripped cpassword from: $($file.FullName)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "    [-] Failed to parse or save XML: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# 2. Alert for scripts (Do not auto-remediate script files to prevent code syntax breakage)
$ScriptFiles = Get-ChildItem -Path $SysvolPath -Include *.vbs, *.ps1, *.bat, *.cmd -Recurse -File -ErrorAction SilentlyContinue
$CredentialPattern = '(?i)\b(password|pwd|adminpwd|syspwd|adminpassword|localadminpwd)\s*=\s*["''][^"'']+\b'

foreach ($file in $ScriptFiles) {
    # Skip our own audit and implementation scripts
    if ($file.Name -like "*Get-GPPSYSVOLPasswords*" -or $file.Name -like "*Remove-GPPSYSVOLPasswords*" -or $file.Name -like "*SYSVOLHoneypot*") {
        continue
    }

    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content -match $CredentialPattern) {
        Write-Host "[WARNING] Script contains hardcoded credential pattern: $($file.FullName)" -ForegroundColor Red
        Write-Host "          Manual intervention is required. Review and delete/rotate credentials in this script." -ForegroundColor Yellow
    }
}

Write-Host "[+] SYSVOL password remediation processing completed." -ForegroundColor Green
```

*To verify that no cpassword files or cleartext script credentials exist in SYSVOL:*

[Download Script: Get-GPPSYSVOLPasswords.ps1](audit_scripts/Get-GPPSYSVOLPasswords.ps1)

```powershell
# Get-GPPSYSVOLPasswords.ps1
# Description: Audits the SYSVOL directory for legacy Group Policy Preference files containing cpassword values and scripts containing cleartext credentials.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing SYSVOL for Group Policy Preference and Script Passwords ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# Retrieve local SYSVOL path from registry
$SysvolReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "Sysvol" -ErrorAction SilentlyContinue
if (-not $SysvolReg) {
    Write-Host "[*] SYSVOL registry path not found. Checking standard share path..." -ForegroundColor Yellow
    $SysvolPath = "C:\Windows\SYSVOL\sysvol"
} else {
    $SysvolPath = $SysvolReg.Sysvol
}

if (-not (Test-Path -Path $SysvolPath)) {
    Write-Host "[-] SYSVOL folder not found at path: $SysvolPath" -ForegroundColor Red
    exit 0 # Not a Domain Controller or SYSVOL not configured, nothing to audit
}

Write-Host "[*] Scanning SYSVOL directory: $SysvolPath" -ForegroundColor White

# 1. Scan for XML files containing 'cpassword'
$GppXmls = Get-ChildItem -Path $SysvolPath -Filter *.xml -Recurse -File -ErrorAction SilentlyContinue
foreach ($file in $GppXmls) {
    # Read the file content safely
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content.Contains("cpassword")) {
        Write-Host "[!] VULNERABLE: Group Policy Preference file contains cpassword attribute: $($file.FullName)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 2. Scan for script files containing cleartext credentials
# Scripts: .vbs, .ps1, .bat, .cmd
$ScriptFiles = Get-ChildItem -Path $SysvolPath -Include *.vbs, *.ps1, *.bat, *.cmd -Recurse -File -ErrorAction SilentlyContinue

# Regex pattern for credentials (e.g. password=, pwd=, adminpwd=)
$CredentialPattern = '(?i)\b(password|pwd|adminpwd|syspwd|adminpassword|localadminpwd)\s*=\s*["''][^"'']+\b'

foreach ($file in $ScriptFiles) {
    # Check if the file is our own audit or implementation scripts (skip those)
    if ($file.Name -like "*Get-GPPSYSVOLPasswords*" -or $file.Name -like "*Remove-GPPSYSVOLPasswords*" -or $file.Name -like "*SYSVOLHoneypot*") {
        continue
    }
    
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content -match $CredentialPattern) {
        Write-Host "[!] VULNERABLE: Script file contains potential cleartext password: $($file.FullName)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] No Group Policy Preference passwords or cleartext scripts found in SYSVOL." -ForegroundColor Green
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **Microsoft Security Bulletin**: [MS14-025 - Vulnerability in Group Policy Preferences Could Allow Elevation of Privilege (2962486)](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
* **ANSSI Active Directory Hardening Guide**: Recommendations on local account password delegation and account cleanup.
* **CIS Control**: CIS Control 5.2 - Unique passwords for administrative accounts; CIS Control 6.4 - Delete orphan/defunct policies.
