# [REQ-PAW-172] Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
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

Privileged Access Workstations (PAWs) host high-privilege administrative sessions where access to Active Directory domain controllers, PKI certificate authorities, and Tier 0 identity assets is executed. Hardware peripherals utilized on PAWs are strictly constrained to high-assurance authentication devices, such as smart card readers, cryptographic hardware security keys (FIDO2/YubiKeys), and dedicated administrative input hardware.

### Technical Threat Vectors & PAW Isolation Assurance
1. **Network Egress & Perimeter Leakage**: In a properly architected Tier 0 environment, PAWs are placed in dedicated management VLANs with firewall rules blocking direct Internet access. When new peripheral hardware is inserted, the default Windows Device Setup Manager (DSM) behavior attempts outbound HTTP/HTTPS connections to Microsoft Windows Metadata and Internet Services (WMIS). These requests fail or trigger firewall alarms, creating egress log noise.
2. **Cryptographic Token & Hardware Disclosure**: The metadata queries transmitted by the DSM include granular Vendor IDs (VID), Product IDs (PID), and device serial numbers. Transmitting these queries externally exposes the specific cryptographic hardware models, firmware revisions, and smart card brands used for Tier 0 multi-factor authentication to third-party CDNs and network eavesdroppers.
3. **Preventing Untrusted Ingestion**: Device metadata packages contain external XML manifests, branding schemas, and companion software prompts. While cryptographically signed, ingesting external metadata into the administrative host creates unnecessary software parsing overhead and increases the attack surface of the local device setup infrastructure.
4. **Enforcing Deterministic Administrative Baselines**: All driver packages, cryptographic minidrivers, and peripheral management tools on a PAW must be deployed exclusively through vetted, pre-approved administrative configuration packages, never dynamically retrieved from consumer-facing Internet services.

Enabling this policy completely disables online metadata queries, ensuring that PAW device setup remains strictly local, silent, and secure.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Connected smart card readers, security keys, and approved administrative peripherals will display generic operating system device class icons instead of OEM branding in administrative interfaces. Cryptographic functionality, smart card logon, FIDO2 authentication, and driver operations are completely unaffected.
* **User Experience**: Completely transparent to administrators during daily operations.
* **Network Impact**: Completely eliminates outbound HTTPS connection attempts targeting Microsoft metadata services (`dmd.metaservices.microsoft.com`).
* **Rollout Recommendations**: Mandatory for all PAW hardware images; apply immediately with zero operational risk.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Device Installation
   ```
4. Double-click **Prevent device metadata retrieval from the Internet**.
5. Select **Enabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtDeviceMetadata.ps1](../implementation_scripts/Configure-PawAtDeviceMetadata.ps1)

```powershell
#Configure-PawAtDeviceMetadata.ps1
# Description: Configures Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs.

Write-Host "Configuring Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Prevent Device Metadata Retrieval from Network applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtDeviceMetadataStatus.ps1](../audit_scripts/Get-PawAtDeviceMetadataStatus.ps1)

```powershell
#Get-PawAtDeviceMetadataStatus.ps1
# Description: Audits Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs.

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
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Hardware Control
* **MITRE ATT&CK**: [T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082/), [T1120: Peripheral Device Discovery](https://attack.mitre.org/techniques/T1120/), [T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
* **Related Controls**: [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md), [REQ-PAW-185: Administrative Templates: Require PIN Pairing for Connect on PAWs](configure-paw-at-connect-pin-pairing.md)
