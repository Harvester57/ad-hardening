# [REQ-END-196] Administrative Templates: Require PIN for Connect Wireless Pairing

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-185](../../07-paws/admin-templates/configure-paw-at-connect-pin-pairing.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Require pin for pairing**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect\Require pin for pairing` -> **Enabled** (Select: `First Time` or `Always`)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect`
    * Value Name: `RequirePinForPairing`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Require PIN on first pairing)

---

## Rationale
The Windows Connect application enables endpoints to function as wireless display receivers using the Miracast standard over Wi-Fi Direct (IEEE 802.11 P2P). While useful for collaborative screen projection in meeting rooms, unauthenticated wireless display pairing introduces severe physical perimeter attack vectors.

### 1. Wi-Fi Direct Wireless Hijacking Threat Vectors
Without mandatory PIN pairing, Wi-Fi Direct connections can be established with minimal or zero physical verification:
* **Over-the-Air Screen Hijacking**: Threat actors equipped with Wi-Fi antennas in adjacent offices, public areas, or parking lots can discover listening Miracast receivers. The attacker can project arbitrary video content, deceptive phishing prompts, or disruptive imagery directly onto corporate workstations or executive display screens.
* **Input Injection via User Input Back Channel (UIBC)**: Miracast supports the User Input Back Channel (UIBC), which allows the connecting device to transmit mouse and keyboard events back to the receiver host. An attacker connecting without authentication could potentially inject keystrokes or mouse clicks to execute commands on the victim workstation.
* **Rogue Peer-to-Peer Network Bridging**: Establishing an unverified Wi-Fi Direct connection creates a temporary peer-to-peer IP link between the endpoint and the connecting device. This link can bridge the internal corporate network onto an unmonitored wireless link, bypassing network perimeter firewalls.

### 2. Mandating Out-of-Band Physical Verification
Enforcing `RequirePinForPairing = 1` mandates out-of-band PIN verification before any wireless projection session is accepted:
* When a remote device requests projection, the Windows host generates a dynamic, cryptographically random numeric PIN displayed on the physical monitor.
* The operator of the transmitting device must physically view the screen and enter the PIN into their device to complete pairing.
* This guarantees that only individuals with physical visibility and authorization in the immediate physical space can establish a wireless projection link, completely thwarting blind remote pairing and wireless hijacking.

### 3. MITRE ATT&CK Mapping
* **T1200 - Direct Network / Hardware Access / Wireless Compromise**: Establishing unauthorized wireless peer-to-peer links via Miracast / Wi-Fi Direct.
* **T1557 - Adversary-in-the-Middle**: Intercepting or hijacking wireless display sessions.
* **T1056.001 - Input Capture: Keylogging / Input Injection**: Malicious input injection through unauthenticated UIBC channels.

---

## Legacy Impact & Compatibility
* **User Experience during Wireless Projection**: When users project their laptop or tablet screen to a hardened Windows display receiver for the first time, they must enter the 4-to-8 digit PIN displayed on the receiving monitor. Subsequent connections can be cached if `First Time` pairing is selected.
* **Network Infrastructure**: The Wi-Fi Direct protocol operates independently of the enterprise corporate Wi-Fi infrastructure; standard corporate LAN connectivity is not impacted.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect`
  * **Require pin for pairing**: Set to `Enabled`
  * Select drop-down value: `First Time` (or `Always` for high-security areas)

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtConnectPinPairing.ps1](../implementation_scripts/Configure-EndAtConnectPinPairing.ps1)

```powershell
#Configure-EndAtConnectPinPairing.ps1
# Description: Configures Administrative Templates: Require PIN for Connect Wireless Pairing.

Write-Host "Configuring Administrative Templates: Require PIN for Connect Wireless Pairing..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Require PIN for Connect Wireless Pairing applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtConnectPinPairingStatus.ps1](../audit_scripts/Get-EndAtConnectPinPairingStatus.ps1)

```powershell
#Get-EndAtConnectPinPairingStatus.ps1
# Description: Audits Administrative Templates: Require PIN for Connect Wireless Pairing.

Write-Host "--- Auditing Administrative Templates: Require PIN for Connect Wireless Pairing ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
$ValueName = "RequirePinForPairing"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.15.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.15.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000318, Windows 11 STIG Rule WN11-CC-000318
* **ANSSI Active Directory Hardening Guide**: Section 3.2 (Restricting unauthenticated wireless protocols and P2P communication)
* **Wi-Fi Alliance**: Wi-Fi Direct and Miracast Security Architecture Standards
