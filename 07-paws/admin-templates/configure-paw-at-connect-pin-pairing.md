# [REQ-PAW-185] Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-196](../../08-endpoints/admin-templates/configure-end-at-connect-pin-pairing.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Require pin for pairing**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect\Require pin for pairing` -> **Enabled** (Select: `Always`)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect`
    * Value Name: `RequirePinForPairing`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Require PIN for pairing)

---

## Rationale
Privileged Access Workstations (PAWs) operate within dedicated administrative perimeters for Tier 0 Active Directory management. Wireless projection capabilities (Miracast over Wi-Fi Direct) introduce serious risks of over-the-air hijacking and unauthenticated input injection if not strictly hardened.

### 1. Eliminating Over-the-Air Hijacking on Administrative Consoles
Unauthenticated Miracast pairing allows nearby wireless devices to project to a host:
* An attacker within Wi-Fi range of a PAW could attempt to initiate a wireless projection session, displaying fraudulent login screens or intercepting operator display output.
* If User Input Back Channel (UIBC) is enabled, the connecting device could inject simulated keystrokes and mouse events directly into the PAW operating system, attempting to execute commands in the administrator's active session.
* Enforcing `RequirePinForPairing = 1` requires the connecting device to submit a dynamic numeric PIN displayed on the PAW's physical display before any pairing is accepted.

### 2. Tightened Tier 0 Wireless Boundary
In high-security administrative environments, unmanaged wireless peer-to-peer protocols represent an unacceptable bypass of physical security:
* PAW hardware should operate over dedicated wired management links. If wireless capabilities are enabled on portable PAWs, mandatory PIN entry prevents blind pairing attempts and ensures complete physical visibility of all connection requests.

### 3. MITRE ATT&CK Mapping
* **T1200 - Direct Network / Hardware Access / Wireless Compromise**: Establishing rogue wireless peer-to-peer tunnels.
* **T1557 - Adversary-in-the-Middle**: Interception of wireless management displays.
* **T1056.001 - Input Capture: Keylogging / Input Injection**: Keystroke and input injection via unauthenticated wireless input back channels.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs are dedicated to directory administration and are not used as wireless conference room display targets.
* **Administrative Operations**: No impact on directory management or remote administrative tools.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect`
  * **Require pin for pairing**: Set to `Enabled`
  * Select drop-down value: `Always` (or `First Time`)

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtConnectPinPairing.ps1](../implementation_scripts/Configure-PawAtConnectPinPairing.ps1)

```powershell
#Configure-PawAtConnectPinPairing.ps1
# Description: Configures Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs.

Write-Host "Configuring Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtConnectPinPairingStatus.ps1](../audit_scripts/Get-PawAtConnectPinPairingStatus.ps1)

```powershell
#Get-PawAtConnectPinPairingStatus.ps1
# Description: Audits Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs.

Write-Host "--- Auditing Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs ---" -ForegroundColor Cyan
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
* **Microsoft Privileged Access Workstation Guidance**: PAW Physical and Wireless Interface Restrictions
