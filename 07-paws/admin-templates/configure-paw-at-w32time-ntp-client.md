# [REQ-PAW-181] Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-192](../../08-endpoints/admin-templates/configure-end-at-w32time-ntp-client.md); for Domain Controllers, refer to [REQ-DC-020](../../02-domain-controllers/configure-pdc-time-sync.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) perform high-consequence administrative operations across Tier 0 infrastructure. Precise timekeeping is a non-negotiable prerequisite for Kerberos ticket validation, security event audit sequencing, and cryptographic certificate verification.

### 1. Guaranteeing Tier 0 Kerberos Authentication Integrity
PAW operators routinely request high-privilege Kerberos Ticket Granting Tickets (TGTs) and service tickets to administer Active Directory Domain Controllers, Certificate Authorities, and Key Storage Providers:
* The Kerberos v5 protocol strictly enforces a maximum clock skew threshold of 300 seconds. If a PAW's local clock drifts beyond 5 minutes, all administrative authentications fail immediately, precipitating management outages or dangerous fallback attempts.
* Threat actors attempting adversary-in-the-middle attacks or offline ticket manipulation rely on clock distortion to bypass validity periods. Enforcing `NtpClient\Enabled = 1` ensures that the PAW continuously synchronizes its clock with authenticating Domain Controllers over the secure domain time hierarchy.

### 2. Forensic Timeline Non-Repudiation for Administrative Auditing
Actions taken on a PAW (such as schema modifications, privilege escalations, or policy deployments) must generate forensically unassailable audit events:
* Accurate log correlation across Tier 0 Security logs, PowerShell Script Block Logging, and centralized SIEM aggregators requires synchronized sub-second timestamping.
* Any time disparity introduces ambiguity during forensic incident analysis, potentially undermining the detection of advanced persistent threats.

### 3. Attack Surface Reduction (NTP Server Elimination)
A dedicated administrative station must never act as a network time provider:
* Running the NTP Server listener (`NtpServer\Enabled = 1`) exposes UDP port 123 on the management VLAN, introducing risks of reflection amplification and time poisoning.
* Enforcing `NtpServer\Enabled = 0` guarantees that the PAW acts exclusively as an NTP consumer, keeping UDP port 123 closed to inbound traffic.

### 4. MITRE ATT&CK Mapping
* **T1558 - Steal or Forge Kerberos Tickets**: Exploiting or inducing clock skew to disrupt ticket validation.
* **T1070.006 - Indicator Removal: Timestomp**: Altering timestamp metadata to mask administrative or unauthorized modifications.
* **T1498.002 - Network Denial of Service: Reflection Amplification**: Weaponizing open UDP network listeners.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs automatically synchronize time with authenticating Domain Controllers using domain time hierarchy protocols (`Nt5DS`). No external internet connectivity is required.
* **Administrative Operations**: Reliable time synchronization prevents Kerberos authentication failures during administrative sessions.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers`
  * **Enable Windows NTP Client**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers`
  * **Enable Windows NTP Server**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtW32timeNtpClient.ps1](../implementation_scripts/Configure-PawAtW32timeNtpClient.ps1)

```powershell
#Configure-PawAtW32timeNtpClient.ps1
# Description: Configures Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs.

Write-Host "Configuring Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtW32timeNtpClientStatus.ps1](../audit_scripts/Get-PawAtW32timeNtpClientStatus.ps1)

```powershell
#Get-PawAtW32timeNtpClientStatus.ps1
# Description: Audits Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs.

Write-Host "--- Auditing Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.102.1, Section 18.9.102.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.102.1, Section 18.9.102.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000310, Windows 11 STIG Rule WN11-CC-000310
* **ANSSI Active Directory Hardening Guide**: Recommendation R35 (Time synchronization and Kerberos integrity)
* **Microsoft Privileged Access Workstation Guidance**: PAW Security Architecture and Infrastructure Baseline
