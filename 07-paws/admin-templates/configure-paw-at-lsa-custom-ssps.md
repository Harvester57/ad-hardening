# [REQ-PAW-176] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-187](../../08-endpoints/admin-templates/configure-end-at-lsa-custom-ssps.md); for complementary LSA Protection, refer to [REQ-PAW-007](../../07-paws/enable-lsa-protection.md)).*
* **Operating Systems**: Windows 10 Enterprise (1903+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Allow Custom SSPs and APs to be loaded into LSASS**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority\Allow Custom SSPs and APs to be loaded into LSASS` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `AllowCustomSSPsAPs`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Prohibit custom SSP and AP loading)

---

## Rationale
Privileged Access Workstations (PAWs) operate in the Tier 0 administrative plane, handling Kerberos Ticket Granting Tickets (TGTs), Smart Card PINs, and administrative authentication tokens for Active Directory Domain Controllers. Protecting the Local Security Authority Subsystem Service (`lsass.exe`) against DLL injection and persistence is a vital baseline defense.

### 1. Guarding Tier 0 Credentials in LSASS Memory
Adversaries who achieve local access on an administrative host routinely seek to intercept high-privilege credentials:
* **The Custom SSP Persistence Technique**: By registering a custom Security Support Provider (SSP) or Authentication Package (AP) in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, adversaries ensure that `lsass.exe` loads their malicious DLL at boot.
* **Harvesting Domain Administrator Credentials**: Because SSPs sit directly inside the authentication pipeline, a malicious SSP intercepts administrative passwords and Kerberos authentications in plaintext, recording them to covert staging directories or transmitting them off-host.
* **Neutralizing In-Memory Injection**: Setting `AllowCustomSSPsAPs = 0` guarantees that the operating system kernel and LSA subsystem unconditionally refuse to load third-party SSP and AP DLLs, closing the registry-based persistence vector.

### 2. Reinforcing LSA Protected Process Light (RunAsPPL)
In conjunction with LSA Protection / RunAsPPL ([REQ-PAW-007](../../07-paws/enable-lsa-protection.md)):
* Disallowing custom SSPs ensures that even if an attacker tampers with registry configuration, `lsass.exe` maintains strict adherence to inbox Microsoft-signed security providers.
* Tier 0 credential operations remain entirely confined to verified, native Windows security components.

### 3. MITRE ATT&CK Mapping
* **T1547.005 - Boot or Logon Autostart Execution: Security Support Provider**: Adversaries registering malicious SSP/AP DLLs in the LSA registry.
* **T1003.001 - OS Credential Dumping: LSASS Memory**: In-memory harvesting of administrative credentials.
* **T1556.002 - Modify Authentication Process: Password Filter DLL**: Tampering with LSA authentication handlers.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs utilize native Windows Kerberos, FIDO2/WebAuthn, and Smart Card Credential Providers that operate through standard Windows APIs without loading third-party SSP DLLs into LSASS.
* **Administrative Operations**: Domain administration consoles, RSAT tools, and privileged logon workflows operate seamlessly.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
  * **Allow Custom SSPs and APs to be loaded into LSASS**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtLsaCustomSsps.ps1](../implementation_scripts/Configure-PawAtLsaCustomSsps.ps1)

```powershell
#Configure-PawAtLsaCustomSsps.ps1
# Description: Configures Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs.

Write-Host "Configuring Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtLsaCustomSspsStatus.ps1](../audit_scripts/Get-PawAtLsaCustomSspsStatus.ps1)

```powershell
#Get-PawAtLsaCustomSspsStatus.ps1
# Description: Audits Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs.

Write-Host "--- Auditing Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "AllowCustomSSPsAPs"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.35.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.35.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000290, Windows 11 STIG Rule WN11-CC-000290
* **ANSSI Active Directory Hardening Guide**: Recommendation R30 (Protection of the Local Security Authority subsystem)
* **Microsoft Privileged Access Workstation Guidance**: PAW LSASS Protection and Memory Hardening Rules
