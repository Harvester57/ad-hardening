# [REQ-END-192] Administrative Templates: Configure Windows Time Service NTP Client and Server

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-181](../../07-paws/admin-templates/configure-paw-at-w32time-ntp-client.md); for Domain Controllers, refer to [REQ-DC-020](../../02-domain-controllers/configure-pdc-time-sync.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Enable Windows NTP Client**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Client` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient`
    * Value Name: `Enabled`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Disable Windows NTP Server**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Server` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer`
    * Value Name: `Enabled`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)

---

## Rationale
The Windows Time Service (`W32Time`) is a core architectural component of Windows security, providing synchronization across domain members, member servers, and directory nodes. Precise timekeeping is mandatory for protocol operation, cryptographic authentication, and forensic integrity.

### 1. Kerberos Ticket Validation and Replay Protection
The Kerberos v5 authentication protocol (RFC 4120) incorporates timestamps into Authenticator tokens exchanged between clients, Key Distribution Centers (KDCs), and target services:
* **Enforcing Kerberos Clock Skew Limits**: Domain Controllers strictly enforce a maximum tolerance of 5 minutes (300 seconds) for computer clock synchronization. If a client workstation's time drifts beyond this threshold, all authentication requests (TGT acquisition, service ticket requests, and mutual session setups) fail immediately with `KRB_AP_ERR_SKEW` (Event ID 4768 / 4769).
* **Forced Fallback to Legacy Protocols**: When Kerberos authentication fails due to clock skew, client applications frequently downgrade authentication to NTLM, exposing the environment to NTLM relay attacks and credential harvesting.
* **Tampering and Ticket Replay**: Adversaries who manipulate client system clocks can attempt to replay captured tickets or invalidate certificate validity checks (e.g., CRL/OCSP expiration validation). Enforcing `NtpClient\Enabled = 1` guarantees that the endpoint continually synchronizes its local clock against authoritative domain time sources.

### 2. Forensic Log Integrity and SIEM Event Correlation
Enterprise detection and response depends entirely on chronologically accurate logging:
* When an endpoint generates Security audit events (e.g., Event ID 4624 logon, Event ID 4688 process execution, Event ID 4672 privilege assignment), inaccurate timestamps disrupt event correlation across SIEM, SOC, and EDR platforms.
* Threat actors deliberately manipulate local system time to obscure the sequence of malicious activities or backdate attacker-created files (timestomping). Maintaining continuous NTP synchronization ensures forensic timeline veracity.

### 3. Closing the NTP Server Listener Attack Surface
Workstations and member servers should never serve time to other network hosts:
* Enabling the NTP server listener on client machines opens UDP port 123 to incoming network traffic.
* Threat actors can exploit unauthenticated UDP 123 listeners for NTP amplification and reflection denial-of-service (DDoS) attacks, or attempt to poison downstream peer clocks.
* Setting `NtpServer\Enabled = 0` closes the UDP 123 listening port, ensuring the system operates purely as a secure consumer of domain time.

### 4. MITRE ATT&CK Mapping
* **T1558 - Steal or Forge Kerberos Tickets**: Disrupting or manipulating system time to interfere with ticket validation and induce legacy fallback.
* **T1070.006 - Indicator Removal: Timestomp**: Modifying process or system time attributes to conceal attacker dwell time.
* **T1498.002 - Network Denial of Service: Reflection Amplification**: Weaponizing open UDP time services for network reflection.

---

## Legacy Impact & Compatibility
* **Active Directory Hierarchy Synchronization**: Domain-joined workstations and member servers automatically query the Active Directory domain hierarchy (synchronizing with authenticating Domain Controllers, which in turn sync with the PDC Emulator holding the external stratum-1 time source). No external internet NTP connectivity is required for domain members.
* **Isolated or Air-Gapped Networks**: On networks without direct internet access, the root domain PDC Emulator must be synchronized with a local hardware GPS or atomic clock source. All domain endpoints will inherit this synchronized time automatically through the domain time provider.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers`
  * **Enable Windows NTP Client**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers`
  * **Enable Windows NTP Server**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtW32timeNtpClient.ps1](../implementation_scripts/Configure-EndAtW32timeNtpClient.ps1)

```powershell
#Configure-EndAtW32timeNtpClient.ps1
# Description: Configures Administrative Templates: Configure Windows Time Service NTP Client and Server.

Write-Host "Configuring Administrative Templates: Configure Windows Time Service NTP Client and Server..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure Windows Time Service NTP Client and Server applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtW32timeNtpClientStatus.ps1](../audit_scripts/Get-EndAtW32timeNtpClientStatus.ps1)

```powershell
#Get-EndAtW32timeNtpClientStatus.ps1
# Description: Audits Administrative Templates: Configure Windows Time Service NTP Client and Server.

Write-Host "--- Auditing Administrative Templates: Configure Windows Time Service NTP Client and Server ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
$ValueName = "Enabled"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
$ValueName = "Enabled"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.102.1, Section 18.9.102.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.102.1, Section 18.9.102.2; CIS Windows Server Benchmark: Section 18.9.102.1, Section 18.9.102.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000310, Windows 11 STIG Rule WN11-CC-000310
* **ANSSI Active Directory Hardening Guide**: Recommendation R35 (Time synchronization and Kerberos integrity)
* **Microsoft Security Baseline**: Windows Time Service Policy Configuration Reference
