# [REQ-PAW-186] Administrative Templates: Credential User Interface Security Protections for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-197](../../08-endpoints/admin-templates/configure-end-at-credui-protections.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are dedicated exclusively to high-privilege Tier 0 Active Directory management tasks. Credential collection interfaces must maintain maximum visual confidentiality and prevent information disclosure regarding administrative identities.

### 1. Eliminating Visual Exposure of Tier 0 Passwords and PINs
The password reveal button allows users to unmask typed characters:
* On a PAW, operators type complex administrative passwords, smart card PINs, and directory restoration secrets. Any visual exposure of these credentials creates high-consequence risks from shoulder surfing, physical surveillance cameras in operations centers, or background screen-sharing utilities.
* Setting `DisablePasswordReveal = 1` permanently disables the reveal button across all CredUI dialogs, ensuring characters remain strictly masked during administrative entry.

### 2. Suppressing Tier 0 Administrative Account Discovery
Default UAC elevation dialogs display tiles for all accounts holding local administrative privileges:
* Displaying valid administrative accounts on screen allows observers or unprivileged processes to enumerate dedicated administrative usernames, emergency break-glass accounts, and administrative naming conventions.
* Setting `EnumerateAdministrators = 0` forces CredUI to present empty username and password fields, requiring the operator to manually supply both credentials. This prevents opportunistic discovery of Tier 0 administrative account names.

### 3. MITRE ATT&CK Mapping
* **T1087.001 - Account Discovery: Local Account**: Discovery of administrative usernames in elevation prompts.
* **T1056.002 - Input Capture: GUI Input Capture**: Visual capture of unmasked administrative credentials.
* **T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control**: Exploiting UAC interface disclosures.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Operators elevating applications must type their administrative account name and credentials manually.
* **Administrative Operations**: No impact on Smart Card or Windows Hello for Business PIN entry; keys and PINs remain masked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface`
  * **Do not display the password reveal button**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface`
  * **Enumerate administrator accounts on elevation**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtCreduiProtections.ps1](../implementation_scripts/Configure-PawAtCreduiProtections.ps1)

```powershell
#Configure-PawAtCreduiProtections.ps1
# Description: Configures Administrative Templates: Credential User Interface Security Protections for PAWs.

Write-Host "Configuring Administrative Templates: Credential User Interface Security Protections for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Credential User Interface Security Protections for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtCreduiProtectionsStatus.ps1](../audit_scripts/Get-PawAtCreduiProtectionsStatus.ps1)

```powershell
#Get-PawAtCreduiProtectionsStatus.ps1
# Description: Audits Administrative Templates: Credential User Interface Security Protections for PAWs.

Write-Host "--- Auditing Administrative Templates: Credential User Interface Security Protections for PAWs ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.22.1, Section 18.10.22.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.22.1, Section 18.10.22.2
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000320, WN10-CC-000325; Windows 11 STIG Rules WN11-CC-000320, WN11-CC-000325
* **ANSSI Active Directory Hardening Guide**: Section 3.1 (Securing interactive authentication interfaces and credential prompts)
* **Microsoft Privileged Access Workstation Guidance**: PAW Visual Confidentiality and Elevation Policy
