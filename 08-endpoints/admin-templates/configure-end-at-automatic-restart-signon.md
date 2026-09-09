# [REQ-END-207] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-196](../../07-paws/admin-templates/configure-paw-at-automatic-restart-signon.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Sign-in and lock last interactive user automatically after a restart**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\Sign-in and lock last interactive user automatically after a restart` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `DisableAutomaticRestartSignOn`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Disabled / ARSO blocked)

---

## Rationale
Automatic Restart Sign-On (ARSO) is a Windows convenience feature designed to streamline post-update maintenance. When an automated Windows Update requires a reboot, ARSO captures the interactive user's credentials, encrypts them via the Local Security Authority (LSA) and Data Protection API (DPAPI), and stages them across the reboot sequence. Upon restart, Winlogon automatically decrypts the credentials, logs the user on in the background, instantiates the user profile, and locks the console.

### 1. In-Memory Credential Exposure and DMA Vulnerabilities
While convenient for consumer devices, ARSO introduces critical vulnerabilities in enterprise environments:
* **Pre-Staged Credential Loading into RAM**: Once ARSO automatically logs the user in, the user's primary Kerberos Ticket Granting Tickets (TGTs), NTLM hashes, DPAPI master keys, and authentication tokens are loaded into physical DRAM and the Local Security Authority Subsystem Service (`lsass.exe`).
* **Unattended Physical Exploitation**: Because the machine sits in an empty office or unattended workstation area while ostensibly locked, an adversary with physical access can exploit Direct Memory Access (DMA) attack vectors (via Thunderbolt, PCIe, or USB4 interfaces using tools like PCILeech) to extract secrets from memory without possessing the user's password.
* **Cold-Boot and Memory Remanence Attacks**: If the host is powered down immediately following an ARSO reboot, sensitive directory keys and cached credentials persist in physical memory modules for several minutes, allowing offline memory extraction.
* **Credential Staging Risks in LSA**: Staging decrypted credential material across a reboot relies on cryptographic keys stored in the registry and TPM. Any vulnerability in the staging implementation exposes stored credentials to offline extraction.

### 2. Enforcing Clean Authentication Boundaries
Setting `DisableAutomaticRestartSignOn = 1` (by configuring the GPO "Sign-in and lock last interactive user automatically after a restart" to **Disabled**) completely eliminates credential staging:
* Post-reboot, the system boots strictly into a clean, unauthenticated Winlogon state.
* No user tokens, Kerberos tickets, or DPAPI keys are instantiated in memory until the user physically presents themselves at the console and completes interactive authentication.

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Scraping credentials instantiated in memory by automated background sign-on.
* **T1200 - Direct Network / Hardware Access**: Physical extraction of volatile memory from unattended machines.
* **T1078 - Valid Accounts**: Misusing persisted session tokens.

---

## Legacy Impact & Compatibility
* **User Experience Post-Update**: Following scheduled overnight patch cycles or automated reboots, client workstations will remain at the standard Windows logon screen. User desktop sessions and background applications (e.g., mail clients, cloud sync engines) will not launch until the user logs on.
* **Patch Verification**: Enterprise management agents (Intune, MECM) continue to receive reboot confirmation and compliance signals from the Windows Update Agent regardless of whether a user session is active.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options`
  * **Sign-in and lock last interactive user automatically after a restart**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtAutomaticRestartSignon.ps1](../implementation_scripts/Configure-EndAtAutomaticRestartSignon.ps1)

```powershell
#Configure-EndAtAutomaticRestartSignon.ps1
# Description: Configures Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO).

Write-Host "Configuring Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO)..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtAutomaticRestartSignonStatus.ps1](../audit_scripts/Get-EndAtAutomaticRestartSignonStatus.ps1)

```powershell
#Get-EndAtAutomaticRestartSignonStatus.ps1
# Description: Audits Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO).

Write-Host "--- Auditing Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "DisableAutomaticRestartSignOn"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.99.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.99.1; CIS Windows Server Benchmark: Section 18.10.99.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000390, Windows 11 STIG Rule WN11-CC-000390
* **ANSSI Active Directory Hardening Guide**: Section 3.1 (Securing local authentication processes and credential lifecycle)
* **Microsoft Security Baseline**: Windows Logon Security Recommendations
