# [REQ-END-197] Administrative Templates: Credential User Interface Security Protections

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-186](../../07-paws/admin-templates/configure-paw-at-credui-protections.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Do not display the password reveal button**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Do not display the password reveal button` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI`
    * Value Name: `DisablePasswordReveal`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Disable password reveal button)
  * **Enumerate administrator accounts on elevation**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Enumerate administrator accounts on elevation` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI`
    * Value Name: `EnumerateAdministrators`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Require username and password)

---

## Rationale
The Windows Credential User Interface (CredUI) handles password collection dialogs and User Account Control (UAC) elevation prompts. In default configurations, CredUI exposes cleartext credentials on screen and leaks local administrative usernames to unprivileged operators.

### 1. Eliminating Cleartext Password Exposure via the Reveal Button
Modern Windows password fields include a password reveal ("eye") button that displays cleartext password characters while pressed:
* **Shoulder Surfing in Enterprise Environments**: In open-plan offices, conference facilities, or remote work locations, bystanders, unauthorized personnel, or cameras can visually record cleartext passwords when the reveal button is engaged.
* **Screen Capture and Collaboration Tools**: Screen sharing during video conferences (Teams, Zoom, Webex), remote desktop sessions, or background malware capturing screen frames can record passwords exposed in plaintext on the display.
* Setting `DisablePasswordReveal = 1` permanently strips the reveal glyph from all CredUI password boxes and system logon prompts, ensuring passwords remain masked under all circumstances.

### 2. Preventing Local Administrator Account Enumeration on Elevation
When a standard user triggers an action requiring administrative elevation, the default UAC prompt enumerates and displays tiles for every member of the local Administrators group:
* **Unauthenticated Account Discovery**: Standard users or malware executing in unprivileged user contexts can trigger a harmless UAC prompt to instantly discover the exact usernames of all local administrator accounts, custom break-glass accounts, and administrative naming conventions.
* **Facilitating Targeted Brute-Force and Spraying**: Armed with validated administrative usernames, attackers can focus credential stuffing, password spraying, or offline Kerberoasting attacks directly on identified targets.
* Setting `EnumerateAdministrators = 0` suppresses the enumeration of administrative accounts. The UAC prompt displays blank username and password fields, forcing the user to know and manually provide both a valid administrative account name and its credentials.

### 3. MITRE ATT&CK Mapping
* **T1087.001 - Account Discovery: Local Account**: Harvesting administrative usernames displayed in UAC elevation dialogs.
* **T1056.002 - Input Capture: GUI Input Capture**: Visual capture or screen recording of unmasked passwords.
* **T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control**: Exploiting UAC information disclosure during privilege escalation workflows.

---

## Legacy Impact & Compatibility
* **User Experience during Elevation**: When standard users or technicians elevate applications on an endpoint, they must type both the administrative username (e.g., `.\admin_local` or `DOMAIN\Tier2Admin`) and the password, rather than selecting an account tile from a list.
* **Password Entry Accuracy**: Users cannot view typed passwords in plaintext; complex passwords must be entered carefully.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface`
  * **Do not display the password reveal button**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface`
  * **Enumerate administrator accounts on elevation**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtCreduiProtections.ps1](../implementation_scripts/Configure-EndAtCreduiProtections.ps1)

```powershell
#Configure-EndAtCreduiProtections.ps1
# Description: Configures Administrative Templates: Credential User Interface Security Protections.

Write-Host "Configuring Administrative Templates: Credential User Interface Security Protections..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Credential User Interface Security Protections applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtCreduiProtectionsStatus.ps1](../audit_scripts/Get-EndAtCreduiProtectionsStatus.ps1)

```powershell
#Get-EndAtCreduiProtectionsStatus.ps1
# Description: Audits Administrative Templates: Credential User Interface Security Protections.

Write-Host "--- Auditing Administrative Templates: Credential User Interface Security Protections ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
$ValueName = "DisablePasswordReveal"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$ValueName = "EnumerateAdministrators"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.22.1, Section 18.10.22.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.22.1, Section 18.10.22.2; CIS Windows Server Benchmark: Section 18.10.22.1, Section 18.10.22.2
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000320, WN10-CC-000325; Windows 11 STIG Rules WN11-CC-000320, WN11-CC-000325
* **ANSSI Active Directory Hardening Guide**: Section 3.1 (Securing interactive authentication interfaces and credential prompts)
* **Microsoft Security Baseline**: Credential User Interface Security Baseline
