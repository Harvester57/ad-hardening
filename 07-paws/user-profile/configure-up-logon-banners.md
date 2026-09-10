# [REQ-PAW-125] User Profile: Interactive Logon Warning Banners for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-136](../../08-endpoints/user-profile/configure-up-logon-banners.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Disable Automatic Restart Sign-On (ARSO)**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Logon Options\Sign-in and lock last interactive user automatically after a restart or cold boot` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `DisableAutomaticRestartSignOn`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block automatic restart sign-on and credential caching)
  * **Interactive Logon Legal Notice Text**:
    * GPO Path: `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message text for users attempting to log on`
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `LegalNoticeText`
    * Value Type: `REG_SZ`
    * Value Data: `"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring."`
  * **Interactive Logon Legal Notice Caption**:
    * GPO Path: `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message title for users attempting to log on`
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `LegalNoticeCaption`
    * Value Type: `REG_SZ`
    * Value Data: `"US Department of Defense Warning Statement"`

---

## Rationale
Privileged Access Workstations (PAWs) operate at the highest classification boundary in the enterprise, dedicated strictly to Tier 0 Active Directory and cloud identity administration. Permitting automated background credential rehydration after reboots, or omitting authoritative legal notice warnings, severely undermines physical device security and legal prosecution capabilities.

### 1. Automatic Restart Sign-On (ARSO) & Tier 0 Credential Defense
In default Windows configurations, Automatic Restart Sign-On (ARSO) caches user credentials in LSA secrets to automatically sign the user back in after a system reboot:
* On a PAW, the logged-on user is a Tier 0 administrative authority (Domain Admin, Enterprise Admin, PKI Administrator).
* If ARSO is active, an unexpected reboot or maintenance restart automatically instantiates the administrator's security context, decrypts their DPAPI master keys, and loads their Kerberos Ticket Granting Ticket (TGT) into `lsass.exe` process memory while the physical station is unattended.
* An attacker with physical access or hardware attack tools (e.g., PCIe DMA adapters, Cold Boot memory freezing) can capture privileged credentials from memory without authenticating.
* Setting `DisableAutomaticRestartSignOn = 1` guarantees that no administrative credentials or access tokens are loaded into volatile memory until an administrator physically presents their smart card or biometric credential and authenticates interactively.

### 2. Legal Notice Jurisprudence & Tier 0 Governance
* Under cyber defense frameworks (NIST SP 800-53 AC-8, DISA STIG, ANSSI R37), high-privilege administrative systems must display a formal, non-bypassable warning banner prior to logon.
* Displaying explicit legal notices establishes that the PAW is a restricted enterprise management system, revokes all expectations of personal privacy, and documents user consent to comprehensive administrative session logging and audit recording.
* This is essential for ensuring legal admissibility and non-repudiation during incident response investigations and criminal cybercrime proceedings.

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Scraping Tier 0 administrative credentials automatically loaded into LSASS via ARSO after reboots.
* **T1556 - Modify Authentication Process**: Subverting automated logon mechanisms.
* **T1078 - Valid Accounts**: Unauthorized use of domain accounts where consent to monitoring has not been legally asserted.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs do not require automated background sign-in. Tier 0 administrators are expected to log in interactively for each administrative session.
* **Zero Disruption**: Standard administrative tasks, RSAT tooling, and Active Directory management operate normally.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options`
  * **Interactive logon: Message text for users attempting to log on**: Enter organizational warning text (e.g., `You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring.`)
  * **Interactive logon: Message title for users attempting to log on**: Enter warning title (e.g., `US Department of Defense Warning Statement`)
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Logon Options`
  * **Sign-in and lock last interactive user automatically after a restart or cold boot**: Set to **Disabled**

4. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Interactive Logon warning banners and disable ARSO on the PAW console:

[Download Script: Configure-PawUplogonbanners.ps1](../implementation_scripts/Configure-PawUplogonbanners.ps1)

```powershell
# Configure-PawUplogonbanners.ps1
Write-Host "Applying User Profile restriction: logon-banners..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText" "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring." "String"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption" "US Department of Defense Warning Statement" "String"

```

*To audit the hardening status:*

[Download Script: Get-PawUplogonbannersStatus.ps1](../audit_scripts/Get-PawUplogonbannersStatus.ps1)

```powershell
# Get-PawUplogonbannersStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "1"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText" "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring."
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption" "US Department of Defense Warning Statement"

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 2.3.7.4, Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 2.3.7.4, Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-SO-000075, Windows 11 STIG Rule WN11-SO-000075, NIST SP 800-53 Control AC-8
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing workstation logon parameters and operational notice banners)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and Credential Isolation
