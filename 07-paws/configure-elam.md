# [REQ-PAW-014] Configure Early Launch Antimalware (ELAM) Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs). *(For Domain Controllers, refer to [REQ-DC-156](../02-domain-controllers/configure-elam.md); for Tier 2 Client Workstations and Member Servers, refer to [REQ-END-028](../08-endpoints/configure-elam.md)).*
* **Operating Systems**: Windows 10 Enterprise, Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **ELAM GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy` -> Enabled
  * **Policy Option**: Select **Good and unknown**
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch`
    * **Value Name**: `DriverLoadPolicy`
    * **Value Type**: `REG_DWORD`
    * **Value Data**: `1`

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated administrative bastions that operate at the pinnacle of the enterprise security architecture (Tier 0). Compromise of a PAW grants adversaries the credentials necessary to commandeer identity infrastructure, cloud tenants, and enterprise directory data.

### 1. Early-Boot Rootkit & BYOVD Threat Model
Attackers attempting to compromise administrative endpoints frequently employ kernel-mode rootkits or Bring Your Own Vulnerable Driver (BYOVD) techniques. Drivers marked as `SERVICE_BOOT_START` (`Start = 0`) initialize before user-mode security services, EDR endpoint agents, and credential isolation boundaries start. Once loaded into Ring 0, an unauthorized driver can:
* Directly manipulate kernel memory structures to subvert Protected Process Light (PPL) for `lsass.exe`.
* Intercept raw keystrokes, smart card PIN entries, and FIDO2 hardware token communications.
* Disable endpoint telemetry and blinding security monitoring agents.
* Modify or bypass Virtualization-Based Security (VBS) hypervisor controls.

### 2. Early Launch Antimalware (ELAM) Mechanics
ELAM establishes early boot-level inspection:
1. An antimalware driver registered as an ELAM boot-start driver (such as Microsoft Defender Antivirus `WdBoot.sys`) is loaded by `winload.efi` before any other boot-start drivers.
2. The ELAM driver registers a kernel initialization callback via `IoRegisterBootDriverCallback`.
3. Every subsequent boot-start driver is passed to the ELAM driver for signature, hash, and certificate verification against local and cloud-attested security intelligence.
4. The ELAM driver returns a classification for each binary:
   * **Good (`0x00000008` / `8`)**: Digitally signed by a trusted certificate and verified clean.
   * **Unknown (`0x00000001` / `1`)**: Unclassified by security intelligence (e.g., specialized OEM driver).
   * **Bad, but required for boot (`0x00000004` / `4`)**: Identified as malware or tampered, but marked boot-critical.
   * **Bad (`0x00000002` / `2`)**: Identified as confirmed malware.

### 3. Tightened PAW Baseline Enforcement ("Good and unknown")
Standard client workstations and member servers typically configure setting `3` (**Good, unknown and bad but critical**) to avoid blue-screen crashes on diverse legacy hardware where an essential driver might be classified as bad-but-critical.

However, for Privileged Access Workstations, this baseline is intentionally **tightened**:
* **Closing the "Bad but Critical" Bypass**: Under value `3`, malware that masquerades as a boot-critical storage or bus driver is permitted to load by the kernel. On a Tier 0 PAW, permitting confirmed malware to initialize under any condition is an unacceptable risk.
* **Enforcing Value `1` ("Good and unknown")**: Value `1` blocks **all** drivers classified as "Bad", including those falsely flagging themselves as boot-critical, while continuing to allow legitimate, unclassified OEM hardware drivers ("Unknown") to load.
* PAWs utilize standardized, certified hardware platforms (e.g., Microsoft Surface, enterprise-grade business workstations) where driver provenance is strictly controlled, eliminating the compatibility risks present in heterogeneous client fleets.

---

## Legacy Impact & Compatibility
* **Third-Party Unsigned Drivers**: Any unsigned driver or driver signed with a revoked certificate will be blocked from loading. If a blocked driver is critical for disk access or display, the system will halt. Ensure all hardware drivers are Authenticode-signed and certified prior to deploying this policy.
* **Firmware and Driver Updates**: When updating firmware or hardware drivers on PAWs, verify that the vendor updates are properly signed by Microsoft WHQL or an enterprise-trusted certificate.

### Pre-Deployment Driver Audit
Execute the following PowerShell command on PAWs to inspect all boot-start drivers and verify their digital signatures:

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
2. Edit the dedicated PAW hardening GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware`
4. In the right pane, double-click **Boot-Start Driver Initialization Policy**.
5. Select **Enabled**.
6. In the **Choose the boot-start drivers that can be initialized** dropdown, select:
   **Good and unknown**
7. Click **Apply**, then **OK**.
8. Link the GPO to the dedicated **PAW** Organizational Unit (`OU=PAWs,OU=Tier0,DC=domain,DC=com`).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally on PAWs to configure the tightened ELAM policy.

[Download Script: Configure-ElamPolicy.ps1](implementation_scripts/Configure-ElamPolicy.ps1)

```powershell
# Configure-ElamPolicy.ps1
# Description: Configures the Early Launch Antimalware (ELAM) boot-start driver load policy on the local system.

Write-Host "Applying ELAM Boot-Start driver initialization policy (Tightened for PAWs)..." -ForegroundColor Cyan

$ElamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $ElamPath)) {
    New-Item -Path $ElamPath -Force | Out-Null
}

Set-ItemProperty -Path $ElamPath -Name "DriverLoadPolicy" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] ELAM Boot-Start driver initialization policy set to 'Good and unknown' (Value = 1)." -ForegroundColor Green
```

---

## Auditing & Verification

### PowerShell Audit Script

Run the following script to verify that the tightened ELAM policy (`DriverLoadPolicy = 1`) is properly enforced.

[Download Script: Get-ElamPolicyStatus.ps1](audit_scripts/Get-ElamPolicyStatus.ps1)

```powershell
# Get-ElamPolicyStatus.ps1
# Description: Audits registry configuration of the Early Launch Antimalware (ELAM) policy on PAWs.

Write-Host "--- Auditing ELAM Boot-Start Policy on PAW ---" -ForegroundColor Cyan

$script:Vulnerable = $false

$Path = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$Name = "DriverLoadPolicy"
$Expected = 1

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
* **Event ID 4**: Driver initialized (Classified as Bad, but required for boot - blocked under tightened PAW policy).
* **Windows Defender Antivirus Log**: `Microsoft-Windows-Windows Defender/Operational` -> **Event ID 2000**: Early launch antimalware driver signature loaded or signature update applied.

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark - Section `18.2.2 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical' or stricter ('Good and unknown')`
* **DoD Windows 10/11 STIG**: Rule `V-220743` (Early Launch Antimalware Boot-Start Driver Initialization Policy)
* **Microsoft Security Guidance**: Securing Privileged Access Workstations (PAW Hardening Guidance)
* **ANSSI AD Hardening Guide**: Operational baseline rules for system boot and driver signature verification.
