# [REQ-END-205] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-194](../../07-paws/admin-templates/configure-paw-at-windows-store-restrictions.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Allow Automatic Download and Installation of Store App Updates**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store\Turn off Automatic Download and Install of updates` -> **Disabled** (Enforces automatic updates)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`
    * Value Name: `AutoDownload`
    * Value Type: `REG_DWORD`
    * Value Data: `4` (Automatic update installation enabled)
  * **Turn off the offer to update to the latest version of Windows**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store\Turn off the offer to update to the latest version of Windows` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`
    * Value Name: `DisableOSUpgrade`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block consumer OS upgrade offers)

---

## Rationale
Modern Windows installations incorporate numerous built-in packaged applications, runtime frameworks, and system extensions (such as Windows Terminal, App Installer, HEVC/VP9 codecs, and Edge WebView2 components) that are serviced through the Microsoft Store infrastructure. Managing store update behaviors is essential to ensure critical vulnerability patching while preventing unmanaged operating system upgrades.

### 1. Continuous Security Patching of Packaged System Components
Disabling automatic updates for Microsoft Store applications leaves endpoints severely exposed:
* **Vulnerabilities in Modern Core Components**: Core Windows utilities and third-party media codecs distributed via the Store frequently suffer from memory corruption and remote code execution vulnerabilities (such as CVE-2023-4863 in WebP processing, and multiple remote execution flaws in Windows Codecs Library).
* **Automated Patch Delivery**: If automatic Store updates are blocked, pre-installed apps and system libraries remain frozen at their build-time versions. Threat actors can exploit these unpatched dependencies to execute arbitrary code or bypass security sandboxes.
* Setting `AutoDownload = 4` (by configuring the GPO "Turn off Automatic Download and Install of updates" to **Disabled**) ensures that the Windows Store service automatically downloads and applies security patches for all installed packaged applications in the background.

### 2. Preventing Unsanctioned Major Operating System Upgrades
Consumer-oriented Windows features frequently present prompts encouraging end users to upgrade to the latest major operating system release (such as moving from Windows 10 to Windows 11):
* **Bypassing Enterprise Change Management**: Uncontrolled operating system upgrades can disrupt critical business operations, introduce software incompatibilities with enterprise line-of-business applications, or break endpoint security software (EDR, antivirus filters, and smart card middleware).
* **Controlled Lifecycle Management**: Setting `DisableOSUpgrade = 1` suppresses all consumer-facing operating system upgrade notifications and offers delivered via the Microsoft Store channel, ensuring that operating system version migrations remain under the strict governance of enterprise patch management systems (such as WSUS, Intune, or MECM).

### 3. MITRE ATT&CK Mapping
* **T1195.002 - Supply Chain Compromise: Compromised Software Dependencies**: Maintaining updated dependencies and system packages to close published CVEs.
* **T1489 - Service Stop / System Disruption**: Preventing uncoordinated OS upgrades that disrupt endpoint security agents and administrative operations.

---

## Legacy Impact & Compatibility
* **Bandwidth and Network Usage**: Packaged app updates are downloaded from Microsoft CDN infrastructure. Organizations utilizing Delivery Optimization or internal WSUS/Connected Cache servers will experience optimized network bandwidth distribution.
* **Administrative Governance**: Enterprise administrators retain authoritative control over OS feature version lifecycles through Windows Update for Business policies or internal deployment task sequences.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off Automatic Download and Install of updates**: Set to `Disabled` (Ensures updates are downloaded automatically)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off the offer to update to the latest version of Windows**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtWindowsStoreRestrictions.ps1](../implementation_scripts/Configure-EndAtWindowsStoreRestrictions.ps1)

```powershell
#Configure-EndAtWindowsStoreRestrictions.ps1
# Description: Configures Administrative Templates: Windows Store Updates and OS Upgrade Restrictions.

Write-Host "Configuring Administrative Templates: Windows Store Updates and OS Upgrade Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 4 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtWindowsStoreRestrictionsStatus.ps1](../audit_scripts/Get-EndAtWindowsStoreRestrictionsStatus.ps1)

```powershell
#Get-EndAtWindowsStoreRestrictionsStatus.ps1
# Description: Audits Administrative Templates: Windows Store Updates and OS Upgrade Restrictions.

Write-Host "--- Auditing Administrative Templates: Windows Store Updates and OS Upgrade Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$ValueName = "AutoDownload"
$ExpectedValue = 4
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$ValueName = "DisableOSUpgrade"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.87.1, Section 18.10.87.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.87.1, Section 18.10.87.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000350, Windows 11 STIG Rule WN11-CC-000350
* **Microsoft Security Baseline**: Windows Store Policy Recommendations
* **ANSSI Active Directory Hardening Guide**: Section 3.3 (Managing system components and software update lifecycles)
