# [REQ-DC-152] Disable Link-Layer Topology Discovery Responder Driver on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery`
    * **Policy**: `Turn on Responder (RSPNDR) driver` -> **Disabled**
  * **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD`
    * `AllowRspndrOnDomain` = `0` (REG_DWORD)
    * `AllowRspndrOnPublicNet` = `0` (REG_DWORD)
    * `EnableRspndr` = `0` (REG_DWORD)
    * `ProhibitRspndrOnPrivateNet` = `0` (REG_DWORD)

---

## Rationale
The Link-Layer Topology Discovery (LLTD) Responder (RSPNDR) network protocol driver listens for topology discovery requests from other computers on the local network and responds with device details, identity information, and link-layer capabilities.

On Tier 0 Domain Controllers:
1. **Device Fingerprinting Prevention**: Enabling the Responder driver allows any workstation or rogue host on the local physical segment to discover the Domain Controller, map its MAC address, determine link characteristics, and identify its role via LLTD probe packets.
2. **Network Protocol Stack Reduction**: Running link-layer responders in the kernel networking stack exposes the server to packet-handling vulnerabilities and potential broadcast flooding attacks.

Disabling the Responder driver (`Turn on Responder (RSPNDR) driver -> Disabled`) ensures that the Domain Controller never advertises itself or responds to link-layer topological queries.

---

## Legacy Impact & Compatibility
* **Network Visibility**: Disabling the Responder driver prevents the Domain Controller from showing up on graphical network topology maps rendered by other Windows clients.
* **No Operational Disruption**: Active Directory authentication, replication, LDAP, DNS, and remote administration tools are completely decoupled from LLTD and remain fully functional.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery`
4. Configure the policy:
   * **Setting**: `Turn on Responder (RSPNDR) driver`
   * **State**: **Disabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable the LLTD Responder driver on the Domain Controller.

[Download Script: Configure-DisableLltdResponderDriver.ps1](../implementation_scripts/Configure-DisableLltdResponderDriver.ps1)

```powershell
# Configure-DisableLltdResponderDriver.ps1
# Description: Disables the LLTD Responder (RSPNDR) driver policy on Domain Controllers.

Write-Host "Disabling LLTD Responder (RSPNDR) Driver..." -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if (-not (Test-Path -Path $LltdPath)) {
    New-Item -Path $LltdPath -Force | Out-Null
}

Set-ItemProperty -Path $LltdPath -Name "AllowRspndrOnDomain" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "AllowRspndrOnPublicNet" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "EnableRspndr" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "ProhibitRspndrOnPrivateNet" -Value 0 -Type DWord -ErrorAction Stop

Write-Host "LLTD Responder Driver disabled successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-LltdResponderDriverStatus.ps1](../audit_scripts/Get-LltdResponderDriverStatus.ps1)

```powershell
# Get-LltdResponderDriverStatus.ps1
# Description: Audits registry configuration of LLTD Responder (RSPNDR) driver on Domain Controllers.

Write-Host "--- Auditing LLTD Responder Driver Status ---" -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
$Expected = @{
    "AllowRspndrOnDomain"        = 0
    "AllowRspndrOnPublicNet"     = 0
    "EnableRspndr"               = 0
    "ProhibitRspndrOnPrivateNet" = 0
}

$IsVulnerable = $false

if (Test-Path -Path $LltdPath) {
    $Reg = Get-ItemProperty -Path $LltdPath -ErrorAction SilentlyContinue
    foreach ($Key in $Expected.Keys) {
        $Val = $Reg.$Key
        $Exp = $Expected[$Key]
        if ($Val -eq $Exp) {
            Write-Host "    [+] $($Key): $($Val) (Expected: $($Exp))" -ForegroundColor Green
        } else {
            Write-Host "    [!] $($Key): $($Val) (Expected: $($Exp))" -ForegroundColor Red
            $IsVulnerable = $true
        }
    }
} else {
    Write-Host "    [!] LLTD Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if ($IsVulnerable) {
    exit 1
} else {
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.6.9.2 (Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled')
* **ANSSI AD Hardening Guide**: Security guidelines to prevent server fingerprinting and link-layer discovery on Tier 0 assets.
