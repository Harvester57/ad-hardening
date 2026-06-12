# Hardening Requirement: Configure Windows Defender Application Control

## Target Scope
* **Applicable Systems**: Tier 2 client workstations.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\System\Device Guard\Deploy Windows Defender Application Control
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\CodeIntegrityPolicyPaths

---

## Rationale
Traditional signature-based antivirus solutions scan for known malware patterns. However, they are easily bypassed by custom, compiled executables, dynamic scripts, or zero-day payloads.

**Windows Defender Application Control (WDAC)** is a kernel-enforced application control framework. Instead of asking "Is this file malicious?", WDAC asks "Is this file explicitly trusted?". 

If WDAC is not configured:
1. **Payload Execution**: Standard users can execute downloaded scripts (e.g., PowerShell, VBScript) or binary files, facilitating initial access.
2. **Antivirus Bypass**: Attackers can run obfuscated code, compile payloads on the target endpoint using built-in Windows compilers (e.g., `csc.exe`), or run memory injection scripts that standard antivirus signatures miss.

Deploying a strict WDAC baseline ensures that only binaries and scripts signed by Microsoft, trusted system developers, or located in protected directories (such as Windows system folders) are allowed to execute.

---

## Legacy Impact & Compatibility
* **Administrative Overhead**: Any new enterprise software must be added to the code integrity trust policy (by digital signature or folder exceptions). Deploying unapproved third-party software will trigger blocks.
* **User Script Blocks**: Administrators and power users cannot write and run custom PowerShell or VBS scripts locally unless the scripts are digitally signed by a trusted certificate in the WDAC policy or run in a directory excluded by the rules.
* **Audit Phase Mandate**: To prevent severe business disruption, WDAC policies must always be deployed in **Audit Mode** first. This logs would-be blocks to the Event Viewer without interrupting execution, allowing administrators to gather a list of required applications and construct rules before shifting to **Enforced Mode**.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To deploy WDAC via Group Policy, the policy XML must first be generated, compiled, and placed in a shared intranet network share.

#### 1. Generate and Compile the Policy (on a Reference Machine)
Run the following PowerShell commands to generate the Microsoft Default Windows baseline policy:
```powershell
# Generate the baseline policy XML
New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -FilePath "C:\WDAC\BaselinePolicy.xml" -UserPEs

# Compile the XML policy into a binary CIP file
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\BaselinePolicy.xml" -BinaryFilePath "C:\WDAC\BaselinePolicy.cip"
```

#### 2. Deploy the Policy via GPO
1. Copy the compiled `BaselinePolicy.cip` file to a local secure directory on the target clients (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`) or host it on a network path.
2. Open the **Group Policy Management Console** (`gpmc.msc`).
3. Create or edit the GPO linked to your workstations OU (e.g., `GPO_Hardening_Workstations`).
4. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
5. Configure the setting:
   * **Policy**: `Deploy Windows Defender Application Control`
   * **Setting**: `Enabled`
   * **Code Integrity Policy File Path**: Enter the path to the policy file (e.g., `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b` or a UNC share path).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to generate a baseline WDAC policy, enable Audit Mode, and configure local registry parameters.

[Download Script: Configure-WDACLocalPolicy.ps1](implementation_scripts/Configure-WDACLocalPolicy.ps1)

```powershell
# Configure-WDACLocalPolicy.ps1
# Generates a baseline local Code Integrity policy and sets it to Audit Mode.

Write-Host "--- Configuring WDAC Local Policy Baseline ---" -ForegroundColor Cyan

# Create working directories
$WdacDir = "C:\Windows\System32\CodeIntegrity"
if (-not (Test-Path $WdacDir)) {
    New-Item -Path $WdacDir -ItemType Directory -Force | Out-Null
}

# 1. Generate the Default Windows Policy
Write-Host "[+] Generating Default Windows code integrity rules..." -ForegroundColor Gray
$PolicyXml = "C:\Windows\Temp\DefaultWindows.xml"
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

Write-Host "[+] Local WDAC baseline policy compiled and deployed to $PolicyBin." -ForegroundColor Green
```

*To audit the running WDAC policy states:*
[Download Script: Test-WDACStatus.ps1](audit_scripts/Test-WDACStatus.ps1)

```powershell
# Test-WDACStatus.ps1
# Audits the local system to check if Code Integrity policies are active.

Write-Host "--- Auditing WDAC Activation State ---" -ForegroundColor Cyan

try {
    # Query WMI class for Code Integrity status
    $CI = Get-CimInstance -Namespace "Root\Microsoft\Windows\CI" -ClassName "MSFT_Sipolicy" -ErrorAction Stop
    Write-Host "`n[+] Found $($CI.Count) active Code Integrity policies." -ForegroundColor Yellow
    
    foreach ($Policy in $CI) {
        # FriendlyName, PolicyID, Enforcer properties
        # FriendlyName or PolicyName depending on OS build
        Write-Host "    - Policy: $($Policy.FriendlyName) | ID: $($Policy.PolicyID) | Enforced: $($Policy.EnforcementMode)" -ForegroundColor Green
    }
} catch {
    Write-Host "    - VULNERABLE: No active Code Integrity / WDAC policies detected on the local system." -ForegroundColor Red
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.8.14.3 (Deploy Windows Defender Application Control)
* **ANSSI AD Hardening Guide**: Recommendations regarding application security and driver/code signing enforcement.
