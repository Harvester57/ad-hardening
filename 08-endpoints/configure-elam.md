# [REQ-END-028] Configure Early Launch Antimalware (ELAM) Policy

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and domain member servers. *(For Domain Controllers, refer to [REQ-DC-156](../02-domain-controllers/configure-elam.md); for Privileged Access Workstations, refer to [REQ-PAW-014](../07-paws/configure-elam.md)).*
* **Operating Systems**: Windows 10 Enterprise, Windows 11 Enterprise, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **ELAM GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy` -> Enabled
  * **Policy Option**: Select **Good, unknown and bad but critical**
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch`
    * **Value Name**: `DriverLoadPolicy`
    * **Value Type**: `REG_DWORD`
    * **Value Data**: `3`

---

## Rationale
Standard enterprise endpoints and domain member servers represent the primary ingress point for adversaries seeking footholds inside an organization. Ensuring boot-level integrity prevents attackers from using persistence mechanisms that bypass user-mode security software.

### 1. Boot-Level Attacks & Rootkits
Malicious software or kernel-level implants that initialize during early boot (using drivers configured with `SERVICE_BOOT_START`) can execute prior to the startup of endpoint detection and response (EDR) sensors, third-party antivirus suites, and user-mode security services (`lsass.exe`, `services.exe`).

By intercepting the early boot chain, an unauthorized driver can:
* Blind EDR telemetry before logging or detection pipelines initialize.
* Deploy rootkit functionality to conceal active processes, network connections, and disk artifacts.
* Exploit Bring Your Own Vulnerable Driver (BYOVD) techniques to disable kernel security mitigations.

### 2. Early Launch Antimalware (ELAM) Architecture
Early Launch Antimalware (ELAM) is a core Windows platform security capability that establishes a trust handoff from UEFI Secure Boot to the Windows kernel:
1. `winload.efi` loads the registered ELAM antimalware driver (e.g., Microsoft Defender Antivirus `WdBoot.sys`) before any third-party boot-start drivers.
2. The ELAM driver registers a system boot driver callback via `IoRegisterBootDriverCallback`.
3. As the operating system initializes boot-start drivers, each binary is evaluated by the ELAM driver and assigned a classification:
   * **Good (`0x00000008` / `8`)**: The driver is signed by an Authenticode certificate and verified clean.
   * **Unknown (`0x00000001` / `1`)**: The driver has not been attested by security intelligence (common for specialized hardware peripherals).
   * **Bad, but required for boot (`0x00000004` / `4`)**: The driver is flagged as malicious or tampered, but marked boot-critical.
   * **Bad (`0x00000002` / `2`)**: The driver is identified as confirmed malware.

### 3. Balanced Policy for General Endpoints and Member Servers
For general client workstations and domain member servers, setting `3` (**Good, unknown and bad but critical**) provides an optimal balance between security enforcement and operational reliability:
* **Broad Fleet Compatibility**: Heterogeneous workstation fleets possess diverse OEM hardware components, audio controllers, specialized graphics cards, and network adapters. Setting `3` ensures that unclassified ("Unknown") drivers and drivers necessary for booting continue to load without generating blue screen of death (BSOD) stop errors.
* **Malware Interception**: Drivers identified as confirmed malware that are not boot-critical are unconditionally blocked from loading into kernel memory.
* *(Note: For dedicated Tier 0 administrative workstations, the policy is tightened to `1` ("Good and unknown") as detailed in [REQ-PAW-014](../07-paws/configure-elam.md)).*

---

## Legacy Impact & Compatibility
* **Driver Digital Signatures**: All boot-start drivers must be signed by Microsoft WHQL or an enterprise-trusted code-signing authority.
* **Specialized Peripherals**: Outdated legacy drivers (e.g., legacy disk controllers or specialized lab equipment interfaces) that lack valid digital signatures or are flagged by antimalware definitions may be blocked from loading. Verify driver signatures across endpoint hardware models prior to enterprise deployment.

### Pre-Deployment Driver Audit
Run the following PowerShell script on representative client workstations and member servers to inspect all installed boot-start drivers and verify their signature status:

```powershell
# Enumerate all boot-start drivers (Start = 0) and verify Authenticode signatures
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\*" |
    Where-Object { $_.Start -eq 0 -and $_.ImagePath } |
    ForEach-Object {
        $rawPath = $_.ImagePath -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '^\\\?\?\\', ''
        $resolvedPath = [System.Environment]::ExpandEnvironmentVariables($rawPath)
        if (-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
            $resolvedPath = Join-Path "$env:SystemRoot\System32" $resolvedPath
        }
        if (Test-Path $resolvedPath) {
            $sig = Get-AuthenticodeSignature -FilePath $resolvedPath
            [PSCustomObject]@{
                ServiceName = $_.PSChildName
                ImagePath   = $resolvedPath
                Status      = $sig.Status
                Signer      = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unsigned" }
            }
        }
    } | Format-Table -AutoSize
```

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO applied to your standard endpoints and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware`
4. In the right pane, double-click **Boot-Start Driver Initialization Policy**.
5. Select **Enabled**.
6. In the **Choose the boot-start drivers that can be initialized** dropdown, select:
   **Good, unknown and bad but critical**
7. Click **Apply**, then **OK**.
8. Link the GPO to the appropriate **Endpoints** and **Member Servers** Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the ELAM boot-start driver load policy on endpoints.

[Download Script: Configure-ElamPolicy.ps1](implementation_scripts/Configure-ElamPolicy.ps1)

```powershell
# Configure-ElamPolicy.ps1
# Description: Configures the Early Launch Antimalware (ELAM) boot-start driver load policy on the local system.

Write-Host "Applying ELAM Boot-Start driver initialization policy..." -ForegroundColor Cyan

$ElamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $ElamPath)) {
    New-Item -Path $ElamPath -Force | Out-Null
}

Set-ItemProperty -Path $ElamPath -Name "DriverLoadPolicy" -Value 3 -Type DWord -ErrorAction Stop
Write-Host "[+] ELAM Boot-Start driver initialization policy set to 'Good, unknown and bad but critical' (Value = 3)." -ForegroundColor Green
```

---

## Auditing & Verification

### PowerShell Audit Script

Run the following script to audit the ELAM driver load policy status.

[Download Script: Get-ElamPolicyStatus.ps1](audit_scripts/Get-ElamPolicyStatus.ps1)

```powershell
# Get-ElamPolicyStatus.ps1
# Description: Audits registry configuration of the Early Launch Antimalware (ELAM) policy.

Write-Host "--- Auditing ELAM Boot-Start Policy ---" -ForegroundColor Cyan

$script:Vulnerable = $false

$Path = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$Name = "DriverLoadPolicy"
$Expected = 3

if (Test-Path $Path) {
    $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $Val = $Reg.$Name
    if ($Val -eq $Expected) {
        Write-Host "  [+] Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Green
    } else {
        Write-Host "  [!] MISMATCH: Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] NOT FOUND: Path $($Path) (Expected: $Name = $Expected)" -ForegroundColor Red
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

## Auditing, Detection & Telemetry
ELAM operational events and driver initialization classifications are logged by the kernel and Windows Defender:
* **Log Name**: `Microsoft-Windows-EarlyLaunchAM/Operational`
* **Event ID 1**: Driver initialized (Classified as Good).
* **Event ID 2**: Driver blocked (Classified as Bad / Malicious).
* **Event ID 3**: Driver initialized (Classified as Unknown).
* **Event ID 4**: Driver initialized (Classified as Bad, but required for boot).
* **Windows Defender Antivirus Log**: `Microsoft-Windows-Windows Defender/Operational` -> **Event ID 2000**: Early launch antimalware driver signature loaded or signature update applied.

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark - Section `18.2.2 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'`
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section `18.2.2 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'`
* **DoD Windows 10/11 STIG**: Rule `V-220743` (Early Launch Antimalware Boot-Start Driver Initialization Policy)
* **DoD Windows Server STIG**: Rule `V-205739` (Early Launch Antimalware Boot-Start Driver Initialization Policy)
* **ANSSI AD Hardening Guide**: Operational baseline rules for system boot and driver signature verification.
