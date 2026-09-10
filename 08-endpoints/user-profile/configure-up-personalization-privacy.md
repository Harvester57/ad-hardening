# [REQ-END-131] User Profile: Personalization and Privacy Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-120](../../07-paws/user-profile/configure-up-personalization-privacy.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Prevent Enabling Lock Screen Camera**:
    * GPO Path: `Computer Configuration\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen camera` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization`
    * Value Name: `NoLockScreenCamera`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block camera invocation from lock screen)
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
Windows personalization and input learning features enhance the consumer user experience by providing voice activation, dynamic lock screen slideshows, camera access, and predictive typing. In an enterprise security environment, these unauthenticated and telemetry-driven features introduce physical reconnaissance vulnerabilities, memory corruption attack surfaces, and persistent keystroke data collection.

### 1. Lock Screen Attack Surface & Codec Vulnerabilities
When a system is locked, the operating system must strictly limit all interactive capabilities:
* **Lock Screen Camera (`NoLockScreenCamera = 1`)**: Bypassing lock screen authentication to access the device webcam allows unauthorized physical bystanders to record office environments, capture visual badges, or photograph secure facilities without logging into the computer.
* **Lock Screen Slideshow (`NoLockScreenSlideshow = 1`)**: Slideshow features continuously parse image collections stored in user profile directories while the machine is locked. Parsing complex graphic file formats (JPEG, PNG, TIFF) in the unauthenticated logon session (`LogonUI.exe` / `dwm.exe`) exposes the system to heap corruption and remote code execution vulnerabilities in graphic rendering libraries (GDI+ or Windows Imaging Component / WIC) if an attacker places a malformed image on the disk.
* **Voice Activation Above Lock (`LetAppsActivateWithVoiceAboveLock = 2`)**: Allowing voice assistants to listen to ambient microphones while locked enables acoustic eavesdropping and allows unauthorized individuals to issue voice commands to read calendar appointments or send messages.

### 2. Input Personalization & Keystroke Telemetry
* **Input Personalization (`AllowInputPersonalization = 0`)**: Windows automatically collects handwriting strokes, typed text dictionaries, and speech patterns to build local and cloud-synchronized personal language models.
* In practice, this feature operates as an operating system-level keystroke logging mechanism, recording user inputs—including passwords, recovery phrases, and sensitive business communication—into local cache databases (`%LocalAppData%\Microsoft\InputPersonalization`).
* Setting `AllowInputPersonalization = 0` terminates input harvesting, protecting confidential user keystrokes from local forensic extraction.

### 3. MITRE ATT&CK Mapping
* **T1056.001 - Input Capture: Keylogging**: Collecting user keystrokes and typing patterns via input personalization databases.
* **T1123 - Audio Capture**: Recording ambient office audio or issuing unauthorized voice commands via lock screen voice assistants.
* **T1125 - Video Capture**: Activating device webcams without interactive authentication.
* **T1204 - User Execution: Malicious File**: Exploiting image codec parsing vulnerabilities via lock screen slideshows.

---

## Legacy Impact & Compatibility
* **Enterprise Lock Screen Consistency**: The lock screen displays a clean, static corporate background or administrative legal notice banner without slideshow transitions or interactive media buttons.
* **Hardware Camera & Microphone Use**: Webcams and microphones remain fully functional inside authenticated desktop sessions (for Microsoft Teams, Zoom, or Webex conferences). Only unauthenticated invocation above the lock screen is blocked.
* **Standard Keyboard & Typing**: Standard typing, spellcheck, and language keyboards operate normally. Only cloud telemetry synchronization and automatic adaptive dictionary harvesting are suppressed.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Administrative Templates \ Control Panel \ Personalization`
  * **Prevent enabling lock screen camera**: Set to **Enabled**
  * **Prevent enabling lock screen slide show**: Set to **Enabled**
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ App Privacy`
  * **Let Windows apps activate with voice above lock**: Set to **Enabled**
  * In the drop-down menu, select: **Force Deny**
* Navigate to: `Computer Configuration \ Administrative Templates \ Control Panel \ Regional and Language Options \ Handwriting personalization`
  * **Turn off automatic learning**: Set to **Enabled**

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Personalization and Privacy restrictions:

[Download Script: Configure-Uppersonalizationprivacy.ps1](../implementation_scripts/Configure-Uppersonalizationprivacy.ps1)

```powershell
# Configure-Uppersonalizationprivacy.ps1
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

[Download Script: Get-UppersonalizationprivacyStatus.ps1](../audit_scripts/Get-UppersonalizationprivacyStatus.ps1)

```powershell
# Get-UppersonalizationprivacyStatus.ps1
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
* **Microsoft Security Guidance**: Windows Personalization and App Privacy Policy Technical Reference
