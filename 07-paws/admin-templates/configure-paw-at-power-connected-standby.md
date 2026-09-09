# [REQ-PAW-178] Administrative Templates: Disable Connected Standby Network Connectivity for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
* **Policy Settings**:
  * Allow network connectivity during connected-standby (on battery)
  * Allow network connectivity during connected-standby (plugged in)
* **Supported On**: Windows 10 (Version 1607) or Windows Server 2016 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9`
* **Registry Values**:
  * `DCSettingIndex` = `0` (REG_DWORD, Disconnect network during standby on battery)
  * `ACSettingIndex` = `0` (REG_DWORD, Disconnect network during standby when plugged in)
* **Vulnerability References**: MITRE ATT&CK: T1200 (Hardware Additions), T1040 (Network Sniffing), T1557 (Adversary-in-the-Middle), T1021 (Remote Services)

---

## Rationale

Privileged Access Workstations (PAWs) are high-assurance hardware platforms dedicated exclusively to Tier 0 directory administration. Modern laptop hardware supporting Modern Standby (S0 Low Power Idle) allows network adapters (Wi-Fi, Ethernet, cellular) to maintain active IP stacks and receive incoming network frames while the machine is sleeping or the lid is closed. Allowing unattended network activity on a PAW directly violates Tier 0 physical and network isolation standards.

### Technical Threat Vectors & PAW Isolation Risks
1. **Unattended Sleep-State Attack Surface**: A PAW must only process network traffic when an authorized administrator is interactively authenticated at the physical console. If Connected Standby is permitted, the TCP/IP stack, SMB client/server, and RPC runtimes remain energized and listen on management subnets while the screen is dark. An attacker or rogue host on the local subnet could exploit sleep-state network vulnerabilities, trigger authentication coercion (PetitPotam/MS-EFSRPC), or probe exposed RPC endpoints completely undetected.
2. **Wi-Fi Beaconing and Probe Leaks in Transit**: When administrative laptops are transported between secure facilities or data centers, active wireless interfaces in Connected Standby continue transmitting probe requests for remembered networks. Attackers in physical proximity can exploit this behavior using rogue Wi-Fi access points (Evil Twin attacks), attempting to establish rogue connections and intercept unencrypted network payloads or inject spoofed DNS responses.
3. **Prevention of Rogue Wake-on-LAN Triggers**: Malicious network frames designed to trigger operating system wake events cannot execute when network connectivity is severed during standby, preventing unauthorized remote power-on maneuvers.
4. **Physical Security Boundary Alignment**: Disabling Connected Standby network connectivity ensures that the instant an administrative laptop lid is closed or the console enters sleep, all network sockets are cleanly dropped, preventing any network interactions until the operator logs in with a smart card or FIDO2 key.

Enforcing Disconnected Standby (`DCSettingIndex = 0` and `ACSettingIndex = 0`) guarantees that all network hardware powers down during sleep states.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Background network tasks (such as mailbox synchronization or background downloads) are suspended while the PAW is in sleep mode. Full connectivity resumes immediately when the administrator opens the lid and unlocks the console.
* **Administrative Impact**: Zero impact on administrative tools, RSAT consoles, or Active Directory management sessions.
* **Hardware Health**: Dramatically preserves laptop battery life and prevents overheating inside laptop cases.
* **Rollout Recommendations**: Mandatory baseline setting for all mobile PAWs; apply immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings
   ```
4. Double-click **Allow network connectivity during connected-standby (on battery)**:
   * Set to **Disabled**.
5. Double-click **Allow network connectivity during connected-standby (plugged in)**:
   * Set to **Disabled**.
6. Click **Apply**, then click **OK** for both policies.
7. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtPowerConnectedStandby.ps1](../implementation_scripts/Configure-PawAtPowerConnectedStandby.ps1)

```powershell
#Configure-PawAtPowerConnectedStandby.ps1
# Description: Configures Administrative Templates: Disable Connected Standby Network Connectivity for PAWs.

Write-Host "Configuring Administrative Templates: Disable Connected Standby Network Connectivity for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Connected Standby Network Connectivity for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtPowerConnectedStandbyStatus.ps1](../audit_scripts/Get-PawAtPowerConnectedStandbyStatus.ps1)

```powershell
#Get-PawAtPowerConnectedStandbyStatus.ps1
# Description: Audits Administrative Templates: Disable Connected Standby Network Connectivity for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Connected Standby Network Connectivity for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$ValueName = "DCSettingIndex"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$ValueName = "ACSettingIndex"
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

Verify the applied policy settings via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" /s
```
Expected output:
```text
DCSettingIndex    REG_DWORD    0x0
ACSettingIndex    REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.33.6.1, Section 18.9.33.6.2
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Power Management
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200/), [T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/), [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1021: Remote Services](https://attack.mitre.org/techniques/T1021/)
* **Related Controls**: [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md), [REQ-PAW-171: Administrative Templates: MSS System and Session Security Protections for PAWs](configure-paw-at-mss-system-protections.md)
