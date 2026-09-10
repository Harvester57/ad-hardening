# [REQ-END-139] User Profile: Secondary Logon Service Lockdown

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-128](../../07-paws/user-profile/configure-up-seclogon-service.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Secondary Logon Service Startup Type**:
    * GPO Path: `Computer Configuration\Windows Settings\Security Settings\System Services\Secondary Logon` -> Set to **Disabled**
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\seclogon`
    * Value Name: `Start`
    * Value Type: `REG_DWORD`
    * Value Data: `4` (Disabled)

---

## Rationale
The Secondary Logon service (`seclogon.dll`, executed within `svchost.exe`) provides the runtime infrastructure that enables the `CreateProcessWithLogonW` and `CreateProcessWithTokenW` Win32 APIs, powering the native Windows `runas.exe` utility and interactive "Run as different user" GUI options. While designed to facilitate administrative convenience, the Secondary Logon service introduces severe local privilege escalation risks and undermines enterprise credential tiering hygiene.

### 1. Secondary Logon Architecture & Token Duplication Vulnerabilities
To launch a process under an alternate user identity, the Secondary Logon service acts as a privileged broker:
* The client application calls `CreateProcessWithLogonW`, transmitting credentials to `seclogon` over local RPC.
* The service calls `LogonUserEx()`, creates a primary access token for the specified user, sets up the new process with the target token, and handles complex security descriptor, token duplication, and desktop window station assignments (`winsta0\default`).
* Because `seclogon` operates as `NT AUTHORITY\SYSTEM` and manages token duplication across disparate integrity levels, it has historically been plagued by high-severity Local Privilege Escalation (LPE) vulnerabilities (notably CVE-2016-0099 / MS16-032, CVE-2020-0683, and CVE-2021-36955). Attackers exploit thread impersonation flaws and unvalidated token handles inside `seclogon` to seize instant SYSTEM access from unprivileged accounts.

### 2. Tiering Architecture & Credential Boundary Defense
From an Active Directory architectural perspective, using "RunAs" from a standard user session on a Tier 2 workstation to execute administrative tools creates an acute credential exposure risk:
* When an administrator invokes `runas /user:DOMAIN\AdminUser powershell.exe` from a standard workstation, the administrative credentials and associated Kerberos Ticket Granting Tickets (TGTs) are loaded into the local workstation's LSASS process memory.
* If the underlying Tier 2 client workstation is compromised by malware or a low-privileged adversary, the administrative credentials can be extracted using tools like Mimikatz, leading to lateral movement and full domain compromise.
* Under the Microsoft Enterprise Access Model and ANSSI hardening standards, administrators must never enter privileged credentials on non-privileged endpoints. Tier 0 and Tier 1 administrators must connect from dedicated PAWs or isolated administrative jump boxes.
* Setting `seclogon` to `Disabled` (`Start = 4`) completely terminates the service attack surface and enforces strict architectural separation between administrative and standard user contexts.

### 3. MITRE ATT&CK Mapping
* **T1134 - Access Token Manipulation**: Abusing token creation and impersonation APIs within secondary logon.
* **T1548 - Abuse Elevation Control Mechanism**: Utilizing alternate credential launching to bypass execution constraints.
* **T1068 - Exploitation for Privilege Escalation**: Exploiting known kernel and service token vulnerabilities in seclogon to achieve SYSTEM access.

---

## Legacy Impact & Compatibility
* **Standard User Workflows**: Standard business users do not require Secondary Logon for day-to-day productivity applications.
* **Administrative Workflows on Client Workstations**: Technicians who previously utilized `RunAs` on end-user machines to install software or perform maintenance must transition to approved remote administration practices (such as PowerShell Remoting / JEA, Windows Admin Center, or dedicated management jump hosts).
* **Gaming and Specialized Software**: Rare legacy software suites or gaming platforms that spawn background updater processes via `CreateProcessWithLogonW` will fail if `seclogon` is disabled. Verify application dependencies prior to wide rollout.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Windows Settings \ Security Settings \ System Services`
4. Double-click **Secondary Logon** and configure:
   * Check **Define this policy setting**
   * Select **Disabled**
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable the Secondary Logon service:

[Download Script: Configure-Upseclogonservice.ps1](../implementation_scripts/Configure-Upseclogonservice.ps1)

```powershell
# Configure-Upseclogonservice.ps1
Write-Host "Applying User Profile restriction: seclogon-service..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Services\seclogon" "Start" "4" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-UpseclogonserviceStatus.ps1](../audit_scripts/Get-UpseclogonserviceStatus.ps1)

```powershell
# Get-UpseclogonserviceStatus.ps1
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
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Services\seclogon" "Start" "4"

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 5.x (System Services); CIS Microsoft Windows 11 Enterprise Benchmark: Section 5.x
* **DISA STIG**: Windows 10 STIG Rule WN10-SV-000125, Windows 11 STIG Rule WN11-SV-000125
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Disabling unnecessary system services and securing workstation boundaries)
* **Microsoft Enterprise Access Model**: Clean Source Principle and Administrative Credential Hygiene
