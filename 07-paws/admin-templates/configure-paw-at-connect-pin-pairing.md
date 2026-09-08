# [REQ-PAW-185] Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing` = `1`

---

## Rationale
The Windows Connect app allows nearby wireless devices to project their screens to the machine over Wi-Fi Direct (Miracast). Requiring a PIN for pairing prevents unauthorized external devices from projecting content or attempting connection hijack attacks without local physical verification.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Users initiating wireless projection must enter the displayed numeric PIN.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect`
  * **Require pin for pairing**: Set to `Enabled` (First Time or Always)

4. Link the GPO to the appropriate Organizational Unit and verify replication.

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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.14.1
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
