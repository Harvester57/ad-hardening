# [REQ-DC-156] Configure Early Launch Antimalware (ELAM) Policy on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0). *(For Privileged Access Workstations, refer to [REQ-PAW-014](../07-paws/configure-elam.md); for Tier 2 Client Workstations and Member Servers, refer to [REQ-END-028](../08-endpoints/configure-elam.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025.

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
Active Directory Domain Controllers serve as the root of trust (Tier 0) for the entire enterprise directory. Early-stage boot integrity is critical to prevent kernel-level compromise before security subsystems initialize.

### 1. The Early Boot Attack Vector & BYOVD Exploits
During system startup, drivers designated as `SERVICE_BOOT_START` (`Start = 0` in registry) load into Ring 0 kernel memory directly from the Windows boot loader (`winload.efi`). These drivers initialize long before:
* Third-party endpoint detection and response (EDR) sensors.
* User-mode security subsystems (`lsass.exe`, `services.exe`).
* Windows Defender real-time protection agents.

Adversaries targeting Domain Controllers leverage Bring Your Own Vulnerable Driver (BYOVD) tactics or rootkit techniques (such as BlackLotus, CosmicStrand, or malicious storage filter drivers) to insert malicious kernel code early in the boot sequence. If a malicious boot-start driver is allowed to load, it can:
* Directly disable LSA Protection (Protected Process Light / PPL) in kernel memory.
* Patch kernel security callbacks (AMSI, ETW Threat Intelligence).
* Intercept raw Active Directory database (`ntds.dit`) read/write operations.
* Subvert Virtualization-Based Security (VBS) and Credential Guard.

### 2. Early Launch Antimalware (ELAM) Architecture
ELAM is a native Windows security architecture designed to bridge the visibility gap between UEFI Secure Boot and the full initialization of the operating system security stack:
1. An ELAM-capable antimalware driver (such as Windows Defender's `WdBoot.sys`) initializes immediately after the operating system kernel and HAL, before any third-party boot drivers.
2. The ELAM driver registers a kernel callback via `IoRegisterBootDriverCallback`.
3. As `winload.efi` and the kernel enumerate all subsequent boot-start drivers, each binary is submitted to the ELAM driver for inspection.
4. The ELAM driver examines the digital signature, hash, and certificate chain against a trusted security intelligence database and classifies each driver into one of four categories:
   * **Good (`0x00000008` / `8`)**: The driver is signed by a trusted certificate and verified clean.
   * **Unknown (`0x00000001` / `1`)**: The driver has not been attested to by security intelligence definitions.
   * **Bad, but required for boot (`0x00000004` / `4`)**: The driver matches known malware signatures, but is flagged as essential to continue system boot (e.g., storage or bus driver).
   * **Bad (`0x00000002` / `2`)**: The driver is identified as known malware.

### 3. Selection of "Good, unknown and bad but critical" for Domain Controllers
The `DriverLoadPolicy` setting controls how the kernel responds to these classifications:
* Setting `3` (**Good, unknown and bad but critical**) ensures that all unclassified and good drivers load normally, and non-critical malware drivers are strictly blocked.
* In enterprise data centers, Domain Controllers typically run on specialized virtualization platforms (VMware ESXi, Hyper-V) or bare-metal servers equipped with hardware RAID controllers, Host Bus Adapters (HBA), or SAN storage drivers.
* Utilizing setting `3` prevents catastrophic domain-wide outages (boot loops or BSODs on storage controllers) while still neutralizing malicious drivers that attempt to establish rootkit persistence.
* *(Note: In contrast, Privileged Access Workstations with dedicated, standardized hardware enforce `1` ("Good and unknown") as documented in [REQ-PAW-014](../07-paws/configure-elam.md) to close the "bad but critical" exemption).*

---

## Legacy Impact & Compatibility
* **Driver Digital Signatures**: All boot-start drivers must possess valid digital signatures recognized by Windows Hardware Quality Labs (WHQL) or the trusted enterprise certificate store.
* **Storage and Virtualization Controllers**: Third-party hypervisor integration components (e.g., legacy virtio, custom storage filter drivers) must be verified prior to enforcement.
* **Reboot Requirement**: Changes to the ELAM policy take effect during the next system reboot when `winload.efi` initializes the boot driver policy.

### Pre-Deployment Boot-Start Driver Audit
Before enforcing the ELAM policy on Domain Controllers, execute the following script to verify the signatures and classifications of all installed boot-start drivers:

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

1. Open the **Group Policy Management Console** (`gpmc.msc`) with Domain Admin credentials.
2. Edit the baseline Domain Controller hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware`
4. In the right pane, double-click **Boot-Start Driver Initialization Policy**.
5. Select **Enabled**.
6. In the **Choose the boot-start drivers that can be initialized** dropdown, select:
   **Good, unknown and bad but critical**
7. Click **Apply**, then **OK**.
8. Link the GPO to the **Domain Controllers** Organizational Unit (`OU=Domain Controllers,DC=domain,DC=com`).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally on Domain Controllers to configure the ELAM boot-start driver policy.

[Download Script: Configure-DcElamPolicy.ps1](implementation_scripts/Configure-DcElamPolicy.ps1)

```powershell
# Configure-DcElamPolicy.ps1
# Description: Configures the Early Launch Antimalware (ELAM) boot-start driver initialization policy on Domain Controllers.

Write-Host "Applying ELAM Boot-Start driver initialization policy on Domain Controller..." -ForegroundColor Cyan

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

Run the following script to verify that the ELAM boot-start driver initialization policy is properly enforced.

[Download Script: Get-DcElamPolicyStatus.ps1](audit_scripts/Get-DcElamPolicyStatus.ps1)

```powershell
# Get-DcElamPolicyStatus.ps1
# Description: Audits registry configuration of the Early Launch Antimalware (ELAM) policy on Domain Controllers.

Write-Host "--- Auditing ELAM Boot-Start Policy on Domain Controller ---" -ForegroundColor Cyan

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
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section `18.2.2 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'`
* **DoD Windows Server STIG**: Rule `V-205739` (Early Launch Antimalware Boot-Start Driver Initialization Policy)
* **Microsoft Security Baseline**: Windows Server Security Baseline (Boot-Start Driver Initialization Policy)
* **ANSSI AD Hardening Guide**: Operational baseline rules for system boot and driver signature verification.
