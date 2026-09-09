# [REQ-END-183] Administrative Templates: Prevent Device Metadata Retrieval from Network

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Low
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Device Installation
* **Policy Name**: Prevent device metadata retrieval from the Internet
* **Supported On**: Windows 7 / Windows Server 2008 R2 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata`
* **Registry Value**: `PreventDeviceMetadataFromNetwork`
* **Value Type**: `REG_DWORD`
* **Value Data**: `1` (0x00000001 = Suppress device metadata retrieval from external network)
* **Vulnerability References**: MITRE ATT&CK: T1082 (System Information Discovery), T1120 (Peripheral Device Discovery), T1041 (Exfiltration Over C2 Channel)

---

## Rationale

When physical or virtual peripherals—such as USB security tokens, smart card readers, external storage media, printers, or network adapters—are connected to a Windows system, the Device Setup Manager (DSM) initiates automated queries to Microsoft Windows Metadata and Internet Services (WMIS). These services deliver OEM-branded device icons, detailed model descriptions, and companion application links displayed in the "Devices and Printers" interface.

### Technical Threat Vectors & Telemetry Exposure
1. **Peripheral Hardware Fingerprinting & Information Disclosure**: Outbound WMIS requests transmit specific hardware identifiers, including Vendor IDs (VID), Product IDs (PID), revision codes, and subsystem identifiers over network channels. Upstream network eavesdroppers, compromised intermediate proxies, or external telemetry monitors can passively inspect these requests to catalogue connected peripheral assets, identify high-assurance hardware tokens (such as FIDO2 authenticators or PKI smart cards), and map internal system hardware architectures.
2. **Uncontrolled Egress Connections**: In regulated or segmented enterprise environments, workstations should not initiate automated outbound connections to public Internet CDNs whenever a user connects peripheral equipment. These spontaneous lookups create noise in proxy logs and firewall egress inspection consoles.
3. **Attack Surface Reduction**: Device metadata packages contain XML manifests, icon binaries, and software staging links. Ingesting and parsing remote metadata packages from public CDNs within the operating system device installer infrastructure creates an unnecessary attack surface against parser vulnerabilities.
4. **Deterministic Device Management**: Corporate device configuration should remain fully deterministic and managed through approved enterprise driver repositories (such as WSUS, SCCM/MECM, or Intune) rather than opportunistic public CDN queries.

Enabling this control forces Windows to rely solely on locally cached driver metadata and generic operating system device classes, eliminating external metadata network requests.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Connected peripherals will display standard generic device icons (e.g., standard generic smart card, printer, or keyboard icon) instead of vendor-branded photorealistic artwork in the Windows shell. Functional device driver installation and hardware operations are completely unaffected; drivers included in the local Driver Store or distributed via corporate management channels install normally.
* **User Experience**: Minimal to zero impact. Users see generic hardware icons in legacy Control Panel applets.
* **Network Impact**: Eliminates outbound HTTP/HTTPS connections targeting `dmd.metaservices.microsoft.com` and related metadata distribution endpoints.
* **Rollout Recommendations**: Can be deployed immediately across all enterprise client workstations and servers with no operational disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Device Installation
   ```
4. Double-click **Prevent device metadata retrieval from the Internet**.
5. Select **Enabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtDeviceMetadata.ps1](../implementation_scripts/Configure-EndAtDeviceMetadata.ps1)

```powershell
#Configure-EndAtDeviceMetadata.ps1
# Description: Configures Administrative Templates: Prevent Device Metadata Retrieval from Network.

Write-Host "Configuring Administrative Templates: Prevent Device Metadata Retrieval from Network..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Prevent Device Metadata Retrieval from Network applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtDeviceMetadataStatus.ps1](../audit_scripts/Get-EndAtDeviceMetadataStatus.ps1)

```powershell
#Get-EndAtDeviceMetadataStatus.ps1
# Description: Audits Administrative Templates: Prevent Device Metadata Retrieval from Network.

Write-Host "--- Auditing Administrative Templates: Prevent Device Metadata Retrieval from Network ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
$ValueName = "PreventDeviceMetadataFromNetwork"
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

### Option C: Manual Verification

Verify the applied policy setting via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork
```
Expected output:
```text
PreventDeviceMetadataFromNetwork    REG_DWORD    0x1
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.7.2
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Device Installation
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082/), [T1120: Peripheral Device Discovery](https://attack.mitre.org/techniques/T1120/), [T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
* **Related Controls**: [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md), [REQ-END-196: Administrative Templates: Require PIN Pairing for Connect](configure-end-at-connect-pin-pairing.md)
