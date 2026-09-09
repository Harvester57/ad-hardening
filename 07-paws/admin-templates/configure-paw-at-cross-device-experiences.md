# [REQ-PAW-174] Administrative Templates: Disable Cross-Device Experiences for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Cross-Device Experiences
* **Policy Name**: Continue experiences on this device
* **Supported On**: Windows 10 (Version 1703) or Windows Server 2016 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
* **Registry Value**: `EnableCdp`
* **Value Type**: `REG_DWORD`
* **Value Data**: `0` (0x00000000 = Cross-Device Experiences / CDP Disabled)
* **Vulnerability References**: MITRE ATT&CK: T1020 (Automated Exfiltration), T1115 (Clipboard Data), T1552 (Unsecured Credentials), T1080 (Taint Shared Content)

---

## Rationale

Privileged Access Workstations (PAWs) provide a dedicated, isolated execution environment for managing Tier 0 Active Directory Domain Services, Public Key Infrastructure (PKI), and critical identity systems. The Windows Connected Devices Platform (CDP / Project Rome) introduces capabilities—such as cross-device task roaming, shared activity feeds, and cloud-synchronized clipboard buffers—that are fundamentally incompatible with the strict tiering and isolation guarantees required on a PAW.

### Technical Threat Vectors & Tier 0 Isolation Risks
1. **Shatering Tiering Boundaries**: PAWs are designed to operate in total isolation from lower-tier workstations (Tier 1/Tier 2) and consumer devices (smartphones, tablets). If CDP is active, an administrator logging into a PAW who shares an identity or companion link with an unmanaged personal device creates an automatic synchronization bridge between Tier 0 and Tier 2/untrusted environments.
2. **Exfiltration of Tier 0 Secrets via Cloud Clipboard**: Administrative workflows frequently involve high-value strings—such as emergency break-glass passwords, LAPS credentials, Kerberos delegation hashes, or PowerShell scripts with embedded tokens. CDP can synchronize clipboard history to cloud graphs or companion mobile devices, completely bypassing network egress blocks and exposing Tier 0 credentials on unmanaged consumer hardware.
3. **Remote Intent Injection & Lateral Movement**: CDP supports remote application launching and inter-device message delivery via Bluetooth Low Energy (BLE) and local Wi-Fi multicast. A compromised lower-tier workstation or mobile device on the same local network could leverage CDP APIs to send intent payloads or open malicious URLs directly on the PAW.
4. **Wireless Egress & Proximity Attacks**: CDP actively broadcasts BLE beacons and initiates Wi-Fi Direct handshakes to discover nearby devices. On hardened PAW hardware, where Bluetooth and unmanaged wireless interfaces must be disabled or strictly constrained, CDP background activities violate wireless security standards.

Disabling CDP ensures the Connected Devices Platform User Service (`CDPUserSvc`) is inert, stopping all local peer discovery and external activity transmission.

---

## Legacy Impact & Compatibility

* **Operational Impact**: All cross-device continuity features ('Continue on PC', cross-device clipboard, Timeline activity roaming) are permanently suppressed. Essential Tier 0 administrative tooling (Active Directory Administrative Center, PowerShell 5.1/7 consoles, RSAT, MMC, Remote Server Administration Tools) operates with zero degradation.
* **User Experience**: Tier 0 operators work in a self-contained, high-assurance desktop session without distraction or unintended cloud synchronization.
* **Network & Firewall Impact**: Halts CDP broadcast discovery packets and prevents attempts to contact Microsoft Project Rome cloud relays over the administrative management network.
* **Rollout Recommendations**: Mandatory for all PAW deployment baselines; zero operational risk for administrative workflows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Cross-Device Experiences
   ```
4. Double-click **Continue experiences on this device**.
5. Select **Disabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtCrossDeviceExperiences.ps1](../implementation_scripts/Configure-PawAtCrossDeviceExperiences.ps1)

```powershell
#Configure-PawAtCrossDeviceExperiences.ps1
# Description: Configures Administrative Templates: Disable Cross-Device Experiences for PAWs.

Write-Host "Configuring Administrative Templates: Disable Cross-Device Experiences for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cross-Device Experiences for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtCrossDeviceExperiencesStatus.ps1](../audit_scripts/Get-PawAtCrossDeviceExperiencesStatus.ps1)

```powershell
#Get-PawAtCrossDeviceExperiencesStatus.ps1
# Description: Audits Administrative Templates: Disable Cross-Device Experiences for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Cross-Device Experiences for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "EnableCdp"
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

### Option C: Manual Verification

Verify the applied policy setting via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp
```
Expected output:
```text
EnableCdp    REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.19.6
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Cross-Device Experiences
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Hardening Controls
* **MITRE ATT&CK**: [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/), [T1115: Clipboard Data](https://attack.mitre.org/techniques/T1115/), [T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/), [T1080: Taint Shared Content](https://attack.mitre.org/techniques/T1080/)
* **Related Controls**: [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md), [REQ-PAW-185: Administrative Templates: Require PIN Pairing for Connect on PAWs](configure-paw-at-connect-pin-pairing.md)
