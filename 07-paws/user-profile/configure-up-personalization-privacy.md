# [REQ-PAW-120] User Profile: Personalization and Privacy Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-131](../../08-endpoints/user-profile/configure-up-personalization-privacy.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Prevent Enabling Lock Screen Camera**:
    * GPO Path: `Computer Configuration\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen camera` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization`
    * Value Name: `NoLockScreenCamera`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Strictly block camera access from lock screen)
  * **Prevent Enabling Lock Screen Slide Show**:
    * GPO Path: `Computer Configuration\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen slide show` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization`
    * Value Name: `NoLockScreenSlideshow`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block image slideshow processing above lock)
  * **Let Windows Apps Activate with Voice Above Lock**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps activate with voice above lock` -> **Enabled** (Value: `Force Deny`)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy`
    * Value Name: `LetAppsActivateWithVoiceAboveLock`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Force Deny / Strictly prevent voice assistant activation while locked)
  * **Turn Off Automatic Input Personalization Learning**:
    * GPO Path: `Computer Configuration\Administrative Templates\Control Panel\Regional and Language Options\Handwriting personalization\Turn off automatic learning` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization`
    * Value Name: `AllowInputPersonalization`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Prohibit keystroke and handwriting telemetry caching)

---

## Rationale
Privileged Access Workstations (PAWs) serve as the trusted execution environment for managing Active Directory Domain Services, forest trusts, and cryptographic root keys. Permitting multimedia sensors, unauthenticated camera feeds, dynamic slideshow image parsing, voice assistants, or keystroke learning databases on a Tier 0 console creates intolerable physical security, acoustic surveillance, and local memory exploitation risks.

### 1. Lock Screen Attack Surface & Codec Exploitation
Operating system components active above the lock screen execute in unauthenticated sessions:
* **Lock Screen Camera (`NoLockScreenCamera = 1`)**: Webcams on PAW consoles present physical surveillance risks. Disabling the lock screen camera ensures that unauthorized physical individuals cannot record administrative enclaves, server rooms, or keycards.
* **Lock Screen Slideshow (`NoLockScreenSlideshow = 1`)**: Slideshow engines parse graphic file formats in the background while the machine is locked. Parsing unvetted image files in `LogonUI.exe` creates an attack surface for zero-day memory corruption bugs in image decoding codecs (e.g., WIC, GDI+). PAWs must display only static, administrative legal notices.
* **Voice Activation Above Lock (`LetAppsActivateWithVoiceAboveLock = 2`)**: Ambient audio monitoring by speech engines on a PAW risks capturing confidential spoken administrative discussions, domain architecture plans, or verbalized recovery codes.

### 2. Eliminating OS Keystroke Logging via Input Personalization
* **Input Personalization (`AllowInputPersonalization = 0`)**: Windows automatically logs typing sequences, handwriting strokes, and speech fragments to construct user-specific language models.
* On a PAW, where operators routinely type domain administrative passwords, Kerberos ticket commands, and recovery keys, allowing the operating system to maintain local keystroke caches creates a high-value target for post-exploitation credential harvesting.
* Enforcing `AllowInputPersonalization = 0` terminates all adaptive typing logs, ensuring that no administrative credential fragments are retained in local cache stores.

### 3. MITRE ATT&CK Mapping
* **T1056.001 - Input Capture: Keylogging**: Harvesting administrative keystrokes via input personalization learning databases.
* **T1123 - Audio Capture**: Acoustic surveillance of administrative conversations via lock screen voice assistants.
* **T1125 - Video Capture**: Activating device webcams without interactive authentication.
* **T1204 - User Execution: Malicious File**: Weaponizing image codec parsing flaws via lock screen slideshows.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Administrative consoles require clean, static desktop interfaces. Personalization features such as slideshows, lock screen widgets, and adaptive typing dictionaries are strictly barred from PAWs by design.
* **Zero Operational Disruption**: Core administrative command-line tools, RSAT snap-ins, and smart card / Windows Hello authentication function with zero disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Administrative Templates \ Control Panel \ Personalization`
  * **Prevent enabling lock screen camera**: Set to **Enabled**
  * **Prevent enabling lock screen slide show**: Set to **Enabled**
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ App Privacy`
  * **Let Windows apps activate with voice above lock**: Set to **Enabled**
  * In the drop-down menu, select: **Force Deny**
* Navigate to: `Computer Configuration \ Administrative Templates \ Control Panel \ Regional and Language Options \ Handwriting personalization`
  * **Turn off automatic learning**: Set to **Enabled**

4. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Personalization and Privacy restrictions on the PAW console:

[Download Script: Configure-PawUppersonalizationprivacy.ps1](../implementation_scripts/Configure-PawUppersonalizationprivacy.ps1)

```powershell
# Configure-PawUppersonalizationprivacy.ps1
Write-Host "Applying User Profile restriction: personalization-privacy..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" "2" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-PawUppersonalizationprivacyStatus.ps1](../audit_scripts/Get-PawUppersonalizationprivacyStatus.ps1)

```powershell
# Get-PawUppersonalizationprivacyStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" "2"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0"

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.1.x, Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.1.x, Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000155, Windows 11 STIG Rule WN11-CC-000155
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and preventing lock screen bypasses)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Sensor Lockdown and Privacy Isolation
