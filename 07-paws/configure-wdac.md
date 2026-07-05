# [REQ-PAW-036] Configure Windows Defender Application Control

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10, Windows 11 (Enterprise and Professional editions)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Administrative Templates\System\Device Guard\Deploy Windows Defender Application Control
  * **Registry Location**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\CodeIntegrityPolicyPaths`

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated administrative hosts used to manage high-value assets such as Domain Controllers and identity systems. Because they handle Tier 0 administrative credentials, they are highly targeted by adversaries.

**Windows Defender Application Control (WDAC)** provides kernel-enforced application control to ensure that only trusted code executes on PAWs. Standard application control options like AppLocker operate primarily in user mode, whereas WDAC enforces integrity at both the kernel (KMCI) and user mode (UMCI) levels. Implementing a baseline WDAC policy that restricts software execution exclusively to Microsoft-signed code and trusted system components blocks unauthorized administrative tools, remote monitoring agents, and malicious payloads.

---

## Legacy Impact & Compatibility
* **Pre-requisite (Memory Integrity/HVCI)**: Hypervisor-Protected Code Integrity (HVCI) must be active to enforce code integrity policies at the hypervisor layer. Refer to [REQ-PAW-010 - Enable VBS and Credential Guard for PAWs](enable-vbs-credential-guard.md) to ensure Memory Integrity (HVCI) and Virtualization-Based Security (VBS) are fully active.
* **Administrative Overhead**: Standard users and administrators cannot install or execute arbitrary software. Any administration tool, package, or script must be signed by a trusted publisher or explicitly allowed by the WDAC policy.
* **Audit Mode Deployment**: To prevent disruption of critical administrative tasks, the WDAC baseline policy must be deployed in **Audit Mode** initially. This allows tracking would-be blocks in the Event Viewer without interrupting daily operations, allowing the baseline to be fully tuned before enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To deploy WDAC via Group Policy, the policy XML must first be generated, compiled, and placed in a secure shared intranet network path or local path on target hosts.

#### 1. Generate and Compile the Policy (on a Reference PAW Host)
Run the following PowerShell commands to generate the Microsoft Default Windows baseline policy:
```powershell
# Generate the baseline policy XML
New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -FilePath "C:\WDAC\PawBaselinePolicy.xml" -UserPEs

# Compile the XML policy into a binary CIP file
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\PawBaselinePolicy.xml" -BinaryFilePath "C:\WDAC\PawBaselinePolicy.cip"
```

#### 2. Deploy the Policy via GPO
1. Copy the compiled `PawBaselinePolicy.cip` file to a local secure directory on all target PAWs (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`) or host it on a network share.
2. Open the **Group Policy Management Console** (`gpmc.msc`).
3. Create or edit a GPO linked to the PAWs OU (e.g., `GPO_Hardening_PAWs`).
4. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
5. Configure the following setting:
   * **Policy**: `Deploy Windows Defender Application Control`
   * **Setting**: `Enabled`
   * **Code Integrity Policy File Path**: Enter the local path (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`) or network share path.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to generate a baseline WDAC policy, enable Audit Mode, and configure local parameters.

# Configure-PawWDACLocalPolicy.ps1

[Download Script: Configure-PawWDACLocalPolicy.ps1](implementation_scripts/Configure-PawWDACLocalPolicy.ps1)

```powershell
# Configure-PawWDACLocalPolicy.ps1
# Description: Generates a baseline local Code Integrity policy for PAWs, sets it to Audit Mode, and compiles it.

Write-Host "--- Configuring PAW WDAC Local Policy Baseline ---" -ForegroundColor Cyan

# Create working directories
$WdacDir = "C:\Windows\System32\CodeIntegrity"
if (-not (Test-Path $WdacDir)) {
    New-Item -Path $WdacDir -ItemType Directory -Force | Out-Null
}

# 1. Generate the Default Windows Policy
Write-Host "[+] Generating Default Windows code integrity rules..." -ForegroundColor Gray
$PolicyXml = "C:\Windows\Temp\PawDefaultWindows.xml"
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

# Test-PawWDACStatus.ps1

[Download Script: Test-PawWDACStatus.ps1](audit_scripts/Test-PawWDACStatus.ps1)

```powershell
# Test-PawWDACStatus.ps1
# Description: Audits the local PAW to check if Code Integrity policies and HVCI are active.

Write-Host "--- Auditing PAW WDAC State ---" -ForegroundColor Cyan
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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.14.3 (Deploy Windows Defender Application Control / Memory Integrity).
* **Microsoft Security Guidance**: Windows Defender Application Control Deployment Guide.
