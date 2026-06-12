# Hardening Requirement: Enable WDAC Driver Blocklist

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Administrative Templates\System\Device Guard\Deploy Windows Defender Application Control
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config` -> `VulnerableDriverBlocklistEnable` = `1` (REG_DWORD)

---

## Rationale
Attackers frequently employ "Bring Your Own Vulnerable Driver" (BYOVD) attacks to bypass Windows kernel protections. In a BYOVD attack, an adversary with administrative privileges installs a legitimate, cryptographically signed third-party driver that contains a known, exploitable vulnerability. The attacker then exploits this vulnerability to execute arbitrary code with kernel privileges, allowing them to disable security agents, dump LSASS memory, or tamper with system integrity.

Enforcing the **Microsoft Vulnerable Driver Blocklist** via Windows Defender Application Control (WDAC) prevents known vulnerable or malicious drivers from loading in kernel space. By restricting the WDAC policy to **Kernel Mode Code Integrity (KMCI) only** (omitting user-mode enforcement), the control shields the system kernel from driver-based exploits without introducing administrative overhead or blocking standard user-mode server applications and utilities.

---

## Legacy Impact & Compatibility
* **Pre-requisite (Memory Integrity/HVCI)**: The vulnerable driver blocklist requires Hypervisor-Protected Code Integrity (HVCI) for secure, hypervisor-enforced validation. Refer to [Enable Credential Guard](enable-credential-guard.md) to ensure Virtualization-Based Security (VBS) and Memory Integrity (HVCI) are fully enabled. Enabling Secure Boot and CPU virtualization features is a strict pre-requisite; refer to [UEFI Firmware Security Hardening](../07-paws/configure-uefi-security.md) and [Hardware Virtualization and DMA Protection](../07-paws/enable-hardware-virtualization-and-dma-protection.md) for firmware settings.
* **Compatibility with Legacy Drivers**: Third-party backup, monitoring, or hardware administration software running deprecated, vulnerable drivers may fail to load. All such software must be updated to use secure, modern drivers.
* **Deployment Testing**: To prevent system instability, the WDAC blocklist policy should be deployed in **Audit Mode** initially to verify that no critical operational drivers are blocked in production before shifting to enforcement mode.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To enforce the driver blocklist across all Domain Controllers, you can deploy the Microsoft recommended block rules as a custom WDAC policy.

1. Download the Microsoft recommended driver block rules XML from the official Microsoft documentation.
2. Edit the XML to ensure it operates in **Audit Mode** first, then convert the XML configuration into a binary format:
```powershell
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\DriverBlocklist.xml" -BinaryFilePath "C:\WDAC\SIPolicy.p7b"
```
3. Copy the compiled `SIPolicy.p7b` file to a secure local path on all target Domain Controllers (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`) or a share.
4. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain management host.
5. Create or edit a GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
6. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
7. Configure the following setting:
   * **Policy**: `Deploy Windows Defender Application Control`
   * **Setting**: `Enabled`
   * **Code Integrity Policy File Path**: Enter the local or network path to the policy file (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`).
8. To ensure the built-in system driver blocklist is active on modern builds, configure the following registry setting via Group Policy Preferences:
   * **Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\CI\Config`
   * **Value Name**: `VulnerableDriverBlocklistEnable`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to enable the Vulnerable Driver Blocklist registry key and ensure proper configuration.

[Download Script: Configure-DriverBlocklist.ps1](implementation_scripts/Configure-DriverBlocklist.ps1)

```powershell
# Configure-DriverBlocklist.ps1
# Description: Enables the Microsoft Vulnerable Driver Blocklist in the registry and validates VBS/HVCI settings.

Write-Host "Applying hardening requirement: Enable WDAC Driver Blocklist..." -ForegroundColor Cyan

# 1. Configure the registry settings to enable the blocklist
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
$ValueName = "VulnerableDriverBlocklistEnable"

if (-not (Test-Path $RegPath)) {
    Write-Host "[+] Creating registry path: $RegPath" -ForegroundColor Gray
    New-Item -Path $RegPath -Force | Out-Null
}

Write-Host "[+] Setting registry value: $ValueName = 1" -ForegroundColor Gray
Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -ErrorAction Stop

# 2. Validate VBS / HVCI Configuration
$ScenariosPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $ScenariosPath) {
    $HvciStatus = Get-ItemProperty -Path $ScenariosPath -Name "Enabled" -ErrorAction SilentlyContinue
    if ($null -ne $HvciStatus -and $HvciStatus.Enabled -eq 1) {
        Write-Host "[+] Pre-requisite Check: Memory Integrity (HVCI) is enabled." -ForegroundColor Green
    } else {
        Write-Host "[!] Warning: Memory Integrity (HVCI) is disabled. The blocklist requires HVCI for hypervisor enforcement." -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Warning: Memory Integrity scenario configuration not found. Check VBS settings." -ForegroundColor Yellow
}

Write-Host "[+] Configuration applied successfully. A reboot is required to activate the blocklist." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-DriverBlocklistStatus.ps1](audit_scripts/Get-DriverBlocklistStatus.ps1)

```powershell
# Get-DriverBlocklistStatus.ps1
# Description: Audits the configuration of the Microsoft Vulnerable Driver Blocklist and HVCI state.

Write-Host "--- Auditing Vulnerable Driver Blocklist ---" -ForegroundColor Cyan
$Vulnerable = $false

# 1. Check registry value
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
$ValueName = "VulnerableDriverBlocklistEnable"

if (Test-Path $RegPath) {
    $RegValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $RegValue -and $RegValue.$ValueName -eq 1) {
        Write-Host "[+] Vulnerable Driver Blocklist is enabled in the registry." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: Vulnerable Driver Blocklist is disabled or not set in the registry." -ForegroundColor Red
        $Vulnerable = $true
    }
} else {
    Write-Host "[!] VULNERABLE: Code Integrity Config registry key does not exist." -ForegroundColor Red
    $Vulnerable = $true
}

# 2. Check HVCI Status
$ScenariosPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $ScenariosPath) {
    $HvciStatus = Get-ItemProperty -Path $ScenariosPath -Name "Enabled" -ErrorAction SilentlyContinue
    if ($null -ne $HvciStatus -and $HvciStatus.Enabled -eq 1) {
        Write-Host "[+] Memory Integrity (HVCI) is enabled." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: Memory Integrity (HVCI) is disabled in the registry." -ForegroundColor Red
        $Vulnerable = $true
    }
} else {
    Write-Host "[!] VULNERABLE: Memory Integrity scenario registry path does not exist." -ForegroundColor Red
    $Vulnerable = $true
}

# 3. Final Verdict
if ($Vulnerable) {
    Write-Host "`n[!] Verification FAILED: The Vulnerable Driver Blocklist is not fully secured." -ForegroundColor Red
} else {
    Write-Host "`n[+] Verification PASSED: The Vulnerable Driver Blocklist and HVCI are correctly configured." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Recommendations on system component code integrity and driver signature enforcement.
* **CIS Microsoft Windows Server Benchmark**: Section 18.8.14.3 / 18.9.31.2 (Deploy Windows Defender Application Control / Memory Integrity).
* **Microsoft Security Guidance**: Microsoft recommended driver block rules documentation.
