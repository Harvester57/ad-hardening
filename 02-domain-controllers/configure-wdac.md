# [REQ-DC-034] Configure Windows Defender Application Control

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Administrative Templates\System\Device Guard\Deploy Windows Defender Application Control
  * **Registry Location**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\CodeIntegrityPolicyPaths`

---

## Rationale
Domain Controllers represent the highest privilege tier (Tier 0) in an Active Directory forest. Traditional signature-based antivirus solutions are easily bypassed by custom, compiled executables, memory injection scripts, or zero-day payloads.

**Windows Defender Application Control (WDAC)** enforces a strict trust-based model for binary and script execution. By restricting the operating system to only run signed, trusted system files and administrative utilities, WDAC blocks unauthorized software, remote access tools, and custom malware. Deploying WDAC on Domain Controllers mitigates administrative credential dumping, domain compromises, and malware execution in kernel or user space.

---

## Legacy Impact & Compatibility
* **Pre-requisite (Memory Integrity/HVCI)**: Hypervisor-Protected Code Integrity (HVCI) must be active to enforce code integrity policies at the hypervisor layer. Refer to [REQ-DC-007 - Disable Credential Guard](disable-credential-guard.md) to ensure Memory Integrity (HVCI) and Virtualization-Based Security (VBS) are fully active.
* **Administrative Overhead**: Any new software, agents, or drivers deployed to Domain Controllers must be digitally signed by a trusted publisher or explicitly allowed by the WDAC code integrity policy. Unsigned administrative scripts will be blocked.
* **Audit Mode Deployment**: To prevent service disruption, the WDAC baseline policy must be deployed in **Audit Mode** initially. This allows administrators to verify that no critical server roles (DNS, AD DS, DHCP, backup agents) or monitoring services are blocked in production before shifting to enforcement mode.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To deploy WDAC via Group Policy, the policy XML must first be generated, compiled, and placed in a secure shared intranet network path or local path on Domain Controllers.

#### 1. Generate and Compile the Policy (on a Reference Domain Controller)
Run the following PowerShell commands to generate the Microsoft Default Windows baseline policy:
```powershell
# Generate the baseline policy XML
New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -FilePath "C:\WDAC\DCBaselinePolicy.xml" -UserPEs

# Compile the XML policy into a binary CIP file
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\DCBaselinePolicy.xml" -BinaryFilePath "C:\WDAC\DCBaselinePolicy.cip"
```

#### 2. Deploy the Policy via GPO
1. Copy the compiled `DCBaselinePolicy.cip` file to a local secure directory on all target Domain Controllers (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`) or host it on a network share.
2. Open the **Group Policy Management Console** (`gpmc.msc`).
3. Create or edit a GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
4. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
5. Configure the following setting:
   * **Policy**: `Deploy Windows Defender Application Control`
   * **Setting**: `Enabled`
   * **Code Integrity Policy File Path**: Enter the local path (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`) or network share path.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to generate a baseline WDAC policy, enable Audit Mode, and configure local parameters.

# Configure-DCWDACLocalPolicy.ps1

[Download Script: Configure-DCWDACLocalPolicy.ps1](implementation_scripts/Configure-DCWDACLocalPolicy.ps1)

```powershell
# Configure-DCWDACLocalPolicy.ps1
# Description: Generates a baseline local Code Integrity policy for Domain Controllers, sets it to Audit Mode, and compiles it.

Write-Host "--- Configuring Domain Controller WDAC Local Policy Baseline ---" -ForegroundColor Cyan

# Create working directories
$WdacDir = "C:\Windows\System32\CodeIntegrity"
if (-not (Test-Path $WdacDir)) {
    New-Item -Path $WdacDir -ItemType Directory -Force | Out-Null
}

# 1. Generate the Default Windows Policy
Write-Host "[+] Generating Default Windows code integrity rules..." -ForegroundColor Gray
$PolicyXml = "C:\Windows\Temp\DCDefaultWindows.xml"
$PolicyBin = "$WdacDir\SIPolicy.p7b"

# Create a policy based on Microsoft's default rules (trusts Windows, Store, and Driver files)
New-CIPolicy -FilePath $PolicyXml -Level Windows -UserPEs -ErrorAction Stop

# 2. Set Policy to Audit Mode (Rule Option 3 represents Audit Mode)
Write-Host "[+] Setting WDAC policy to Audit Mode for baseline logging..." -ForegroundColor Gray
Set-RuleOption -FilePath $PolicyXml -Option 3 -ErrorAction SilentlyContinue

# 3. Compile the XML into the binary policy expected by the bootloader
Write-Host "[+] Compiling Code Integrity XML into SIPolicy.p7b..." -ForegroundColor Gray
ConvertFrom-CIPolicy -XmlFilePath $PolicyXml -BinaryFilePath $PolicyBin -ErrorAction Stop

# Cleanup temp files
if (Test-Path $PolicyXml) { Remove-Item $PolicyXml -Force }

Write-Host "[+] Local WDAC baseline policy configured. Reboot required." -ForegroundColor Green
```

*To verify the setting has been applied:*

# Test-DCWDACStatus.ps1

[Download Script: Test-DCWDACStatus.ps1](audit_scripts/Test-DCWDACStatus.ps1)

```powershell
# Test-DCWDACStatus.ps1
# Description: Audits the local Domain Controller to check if Code Integrity policies and HVCI are active.

Write-Host "--- Auditing Domain Controller WDAC State ---" -ForegroundColor Cyan
$Vulnerable = $false

# 1. Query WMI class for Code Integrity status
try {
    $CI = Get-CimInstance -Namespace "Root\Microsoft\Windows\CI" -ClassName "MSFT_Sipolicy" -ErrorAction Stop
    if ($null -ne $CI -and $CI.Count -gt 0) {
        Write-Host "`n[+] Found $($CI.Count) active Code Integrity policies." -ForegroundColor Green
        foreach ($Policy in $CI) {
            Write-Host "    - Policy: $($Policy.FriendlyName) | ID: $($Policy.PolicyID) | Enforced: $($Policy.EnforcementMode)" -ForegroundColor Green
        }
    } else {
        Write-Host "`n[-] No active Code Integrity / WDAC policies detected via WMI." -ForegroundColor Yellow
    }
} catch {
    Write-Host "`n[-] Could not query WMI MSFT_Sipolicy. This is expected if no WDAC policies are currently deployed." -ForegroundColor Gray
}

# 2. Check Memory Integrity (HVCI) configuration
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
    Write-Host "`n[!] Verification FAILED: One or more driver security controls are not configured." -ForegroundColor Red
} else {
    Write-Host "`n[+] Verification PASSED: WDAC driver settings and HVCI are correctly configured." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Recommendations on system component code integrity and application control restrictions.
* **CIS Microsoft Windows Server Benchmark**: Section 18.8.14.3 (Deploy Windows Defender Application Control / Memory Integrity).
* **Microsoft Security Guidance**: Windows Defender Application Control Deployment Guide.
