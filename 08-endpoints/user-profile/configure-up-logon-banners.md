# [REQ-END-136] User Profile: Interactive Logon Warning Banners

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-125](../../07-paws/user-profile/configure-up-logon-banners.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Interactive logon configurations govern the initial security boundary when an operator or user accesses the Windows console. Two critical security parameters are enforced: disabling Automatic Restart Sign-On (ARSO) to protect credentials in memory across reboots, and enforcing legally binding pre-logon warning banners to establish authorization boundaries and consent to monitoring.

### 1. Automatic Restart Sign-On (ARSO) & LSASS Exposure
Automatic Restart Sign-On (ARSO) was introduced to streamline the user experience after automated Windows Updates:
* When ARSO is enabled, Windows extracts an encrypted representation of the user's password and stores it in LSA Secrets (`LSA Iso` / registry DPAPI secrets).
* Upon reboot or cold boot, the Winlogon subsystem (`winlogon.exe`) automatically logs the user in in the background, locks the console session, and launches background user applications.
* **Threat Mechanics**: While the console appears locked, the user's primary access tokens, Kerberos Ticket Granting Tickets (TGTs), and DPAPI master keys are already loaded into the Local Security Authority Subsystem Service (`lsass.exe`) process memory.
* If a laptop is lost, stolen, or rebooted in an untrusted environment, an adversary with physical access can execute Cold Boot attacks, DMA dumping, or post-exploitation memory extraction against LSASS without ever needing to know the user's password or PIN.
* Setting `DisableAutomaticRestartSignOn = 1` forces Winlogon to stop caching credentials for automatic restart, ensuring that no user session or credential tokens are instantiated in memory until an interactive, authenticated logon occurs.

### 2. Legal Notice Banners & Legal Admissibility
* Under international cybercrime statutes (e.g., US Computer Fraud and Abuse Act / CFAA, European NIS2 directives, and judicial evidentiary rules), unauthorized adversaries prosecuted for system compromise frequently assert "implied consent" or lack of notification regarding authorized use boundaries.
* Displaying a non-bypassable pre-logon warning banner that requires active acknowledgment before presenting the credential prompt:
  * Expressly revokes any expectation of privacy on corporate assets.
  * Formalizes user consent to administrative monitoring, logging, and inspection.
  * Satisfies mandatory defense compliance benchmarks (DISA STIG, NIST SP 800-53 AC-8).

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Scraping credentials automatically loaded into LSASS via ARSO after reboots.
* **T1556 - Modify Authentication Process**: Subverting automated logon mechanisms.
* **T1078 - Valid Accounts**: Unauthorized use of domain accounts where consent to monitoring has not been legally asserted.

---

## Legacy Impact & Compatibility
* **User Logon Experience**: After a system reboot or Windows Update, users will see the legal notice dialog and must click "OK" before entering their credentials, and applications will not automatically pre-launch in the background until the user signs in.
* **Patch Management**: Automated software updates that reboot systems overnight will leave machines sitting at the logon prompt rather than logged in and locked. This is the desired enterprise security behavior.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options`
  * **Interactive logon: Message text for users attempting to log on**: Enter organizational warning text (e.g., `You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring.`)
  * **Interactive logon: Message title for users attempting to log on**: Enter warning title (e.g., `US Department of Defense Warning Statement`)
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Logon Options`
  * **Sign-in and lock last interactive user automatically after a restart or cold boot**: Set to **Disabled**

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Interactive Logon warning banners and disable ARSO:

[Download Script: Configure-Uplogonbanners.ps1](../implementation_scripts/Configure-Uplogonbanners.ps1)

```powershell
# Configure-Uplogonbanners.ps1
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

[Download Script: Get-UplogonbannersStatus.ps1](../audit_scripts/Get-UplogonbannersStatus.ps1)

```powershell
# Get-UplogonbannersStatus.ps1
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 2.3.7.4, Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 2.3.7.4, Section 18.9.x; CIS Windows Server Benchmark: Section 2.3.7.4
* **DISA STIG**: Windows 10 STIG Rule WN10-SO-000075, Windows 11 STIG Rule WN11-SO-000075, NIST SP 800-53 Control AC-8
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing workstation logon parameters and operational notice banners)
* **Microsoft Security Guidance**: Windows Logon Options: Winlogon Automatic Restart Sign-On (ARSO) Architecture
