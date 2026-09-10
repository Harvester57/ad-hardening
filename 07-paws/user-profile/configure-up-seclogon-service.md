# [REQ-PAW-128] User Profile: Secondary Logon Service Lockdown for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-139](../../08-endpoints/user-profile/configure-up-seclogon-service.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are architected according to the "Clean Source" principle: a PAW is dedicated strictly to a single administrative tier, and administrators log in directly with their Tier 0 credentials. The Secondary Logon service (`seclogon.dll`), which facilitates `RunAs` and `CreateProcessWithLogonW`, is not only unnecessary on a dedicated PAW console, but poses an acute attack surface and violates Tier 0 credential hygiene.

### 1. Secondary Logon Architecture & Token Duplication Vulnerabilities
The Secondary Logon service runs as `NT AUTHORITY\SYSTEM` to broker credential validation and process generation across disparate logon sessions:
* `seclogon` receives user credentials over RPC, calls `LogonUserEx()`, creates a primary token, and establishes a new process tree attached to the active desktop station (`winsta0\default`).
* Because the service handles security access token duplication, thread impersonation, and process handle creation across privilege boundaries, it has historically presented a recurring target for Local Privilege Escalation (LPE) exploits (such as MS16-032 / CVE-2016-0099, CVE-2020-0683, and CVE-2021-36955).
* On a Tier 0 PAW console, running unneeded background services with complex token-handling logic creates an unnecessary vector for privilege escalation and memory tampering.

### 2. Tier 0 Architectural Purity & Credential Cleanliness
* **Eliminating Multi-Identity Anti-Patterns**: On a properly designed PAW, an administrator never logs in with a standard low-privilege user account and elevates individual tools with a Tier 0 account via `RunAs`. Instead, the administrator signs in directly with their dedicated Tier 0 administrative identity (e.g., via smart card or Windows Hello for Business).
* **Guarding Process Tree Integrity**: Disabling `seclogon` prevents any local software from invoking `CreateProcessWithLogonW` or `CreateProcessWithTokenW`, ensuring that all process execution paths originate directly from the authenticated interactive session without intermediate service token duplication.
* **Surface Reduction**: Disabling the service shuts down its RPC endpoint and stops the associated DLL from being loaded into memory.

### 3. MITRE ATT&CK Mapping
* **T1134 - Access Token Manipulation**: Abusing token creation and impersonation APIs within secondary logon.
* **T1548 - Abuse Elevation Control Mechanism**: Utilizing alternate credential launching to bypass execution constraints.
* **T1068 - Exploitation for Privilege Escalation**: Exploiting known kernel and service token vulnerabilities in seclogon to achieve SYSTEM access on the PAW.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAW users do not utilize `RunAs` to alternate between administrative accounts. Each PAW is deployed for dedicated tier-specific administration.
* **Zero Disruption**: Standard RSAT tools, PowerShell remoting, and Active Directory administrative MMC consoles function seamlessly with `seclogon` disabled.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Windows Settings \ Security Settings \ System Services`
4. Double-click **Secondary Logon** and configure:
   * Check **Define this policy setting**
   * Select **Disabled**
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable the Secondary Logon service on the PAW console:

[Download Script: Configure-PawUpseclogonservice.ps1](../implementation_scripts/Configure-PawUpseclogonservice.ps1)

```powershell
# Configure-PawUpseclogonservice.ps1
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

[Download Script: Get-PawUpseclogonserviceStatus.ps1](../audit_scripts/Get-PawUpseclogonserviceStatus.ps1)

```powershell
# Get-PawUpseclogonserviceStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and disabling unnecessary system services)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and Identity Hygiene
