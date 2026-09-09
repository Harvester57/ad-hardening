# [REQ-PAW-196] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-207](../../08-endpoints/admin-templates/configure-end-at-automatic-restart-signon.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) process the enterprise's most sensitive credentials, including Active Directory Domain Admin tokens, Kerberos krbtgt keys, and enterprise root CA certificates. Permitting any automated, unattended credential persistence across reboots is fundamentally incompatible with Tier 0 security architectures.

### 1. Eliminating Tier 0 Credential Exposure in Memory
Automatic Restart Sign-On (ARSO) caches user credentials across reboot cycles to automatically log on and lock the machine:
* On a PAW, allowing automated logon instantiates full administrative tokens, Kerberos service tickets, and LSA secrets directly into physical DRAM while the device sits unattended.
* An adversary gaining physical access to the unattended administrative host can execute Direct Memory Access (DMA) attacks via external PCIe/Thunderbolt controllers or cold-boot attacks to extract Tier 0 tickets from memory.
* Furthermore, ARSO relies on staging decrypted secrets within the LSA and TPM subsystems. Any memory analysis or hardware-level tapping could recover staged administrative secrets.
* Setting `DisableAutomaticRestartSignOn = 1` guarantees that the PAW halts strictly at an unauthenticated logon screen following every reboot.

### 2. Enforcing Strict Physical Presence and Hardware Token Re-Authentication
Hardened administrative access demands deliberate, verifiable human presence:
* Tier 0 operators must re-authenticate explicitly using physical hardware tokens (such as FIDO2 security keys or PIV/CAC smart cards) following any system reboot or maintenance event.
* Automated logon features bypass physical possession checks and must be comprehensively suppressed.

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Intercepting privileged credentials loaded into volatile memory by automated logon.
* **T1200 - Direct Network / Hardware Access**: Physical memory extraction from unattended administrative workstations.
* **T1078 - Valid Accounts**: Misusing unattended administrative session states.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Following any scheduled reboot or update, the PAW will remain at the initial Windows logon screen until the administrator physically logs in.
* **Administrative Operations**: Preserves zero-trust administrative principles without impacting legitimate remote management of Domain Controllers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options`
  * **Sign-in and lock last interactive user automatically after a restart**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtAutomaticRestartSignon.ps1](../implementation_scripts/Configure-PawAtAutomaticRestartSignon.ps1)

```powershell
#Configure-PawAtAutomaticRestartSignon.ps1
# Description: Configures Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs.

Write-Host "Configuring Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtAutomaticRestartSignonStatus.ps1](../audit_scripts/Get-PawAtAutomaticRestartSignonStatus.ps1)

```powershell
#Get-PawAtAutomaticRestartSignonStatus.ps1
# Description: Audits Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.99.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.99.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000390, Windows 11 STIG Rule WN11-CC-000390
* **Microsoft Privileged Access Workstation Guidance**: PAW Physical Security and Credential Lifecycle Architecture
