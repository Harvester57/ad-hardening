# [REQ-END-187] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-176](../../07-paws/admin-templates/configure-paw-at-lsa-custom-ssps.md); for complementary LSA Protection, refer to [REQ-END-007](../../08-endpoints/enable-lsa-protection.md)).*
* **Operating Systems**: Windows 10 (1903 and above) Enterprise/Professional, Windows 11 Enterprise/Pro, Windows Server 2019, 2022, and 2025.

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
The Local Security Authority Subsystem Service (`lsass.exe`) is the central authentication authority in the Windows operating system, responsible for credential validation, token creation, and interactive logons. Security Support Providers (SSPs) and Authentication Packages (APs) execute as dynamic link libraries (DLLs) directly inside the `lsass.exe` memory space.

### 1. The Custom SSP/AP Persistence and Credential Theft Threat Vector
Adversaries with administrative access frequently target the LSA subsystem for persistent credential harvesting:
* **In-Memory Credential Interception**: Threat actors register custom SSP DLLs (e.g., Mimikatz `memssp` or custom malicious security packages) by adding their names to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` or `Authentication Packages`.
* **Execution Inside LSASS**: During system boot or upon explicit dynamic loading, `lsass.exe` loads the registered DLL into its process address space. Because the custom SSP receives plaintext user credentials, Kerberos tickets, and NTLM hashes during logon processing, it can log cleartext credentials to an unencrypted file or exfiltrate them across the network.
* **Persistent Evasion**: Unlike transient LSASS memory scraping tools (which trigger EDR memory read alerts), a registered SSP operates legitimately within the authentication pipeline, surviving system reboots and operating with full system privileges.

### 2. Mandatory Prohibition of Third-Party LSA Extension Libraries
Setting `AllowCustomSSPsAPs = 0` (by configuring the GPO "Allow Custom SSPs and APs to be loaded into LSASS" to **Disabled**) enforces strict inbox validation:
* The Local Security Authority kernel loader strictly refuses to load any custom or third-party SSP or AP DLL into `lsass.exe`, even if registered by an administrator or malware in the registry.
* Only core, Microsoft-signed inbox security providers (such as `msv1_0.dll`, `kerberos.dll`, `schannel.dll`, and `cloudAP.dll`) are permitted to execute within LSASS.
* When combined with LSA Protection / RunAsPPL ([REQ-END-007](../../08-endpoints/enable-lsa-protection.md)), this control completely neutralizes SSP-based DLL injection and persistent credential theft.

### 3. MITRE ATT&CK Mapping
* **T1547.005 - Boot or Logon Autostart Execution: Security Support Provider**: Adversaries registering malicious SSP/AP DLLs in the LSA registry.
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Intercepting in-memory plaintext credentials during logon events.
* **T1556.002 - Modify Authentication Process: Password Filter DLL**: Tampering with authentication packages to log credentials.

---

## Legacy Impact & Compatibility
* **Modern Authentication Platforms**: Modern enterprise multi-factor authentication (MFA) agents, smart card middleware, and FIDO2 authentication solutions integrate with Windows via the **Credential Provider architecture** (`ICredentialProvider`), which operates in `winlogon.exe` and does not require injecting custom SSPs into `lsass.exe`.
* **Legacy Smart Card and Biometric Drivers**: Obsolete third-party authentication solutions developed prior to Windows 10 that rely on custom in-process LSASS AP DLLs will fail to initialize. Organizations must upgrade to modern Credential Providers or native Windows Hello for Business infrastructure.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
  * **Allow Custom SSPs and APs to be loaded into LSASS**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtLsaCustomSsps.ps1](../implementation_scripts/Configure-EndAtLsaCustomSsps.ps1)

```powershell
#Configure-EndAtLsaCustomSsps.ps1
# Description: Configures Administrative Templates: Block Custom SSPs and APs from Loading into LSASS.

Write-Host "Configuring Administrative Templates: Block Custom SSPs and APs from Loading into LSASS..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtLsaCustomSspsStatus.ps1](../audit_scripts/Get-EndAtLsaCustomSspsStatus.ps1)

```powershell
#Get-EndAtLsaCustomSspsStatus.ps1
# Description: Audits Administrative Templates: Block Custom SSPs and APs from Loading into LSASS.

Write-Host "--- Auditing Administrative Templates: Block Custom SSPs and APs from Loading into LSASS ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.35.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.35.1; CIS Windows Server Benchmark: Section 18.9.35.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000290, Windows 11 STIG Rule WN11-CC-000290
* **ANSSI Active Directory Hardening Guide**: Recommendation R30 (Protection of the Local Security Authority subsystem)
* **Microsoft Security Baseline**: Local Security Authority Subsystem Security Policy Recommendations
