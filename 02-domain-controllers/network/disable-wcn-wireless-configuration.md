# [REQ-DC-154] Disable Windows Connect Now Wireless Settings Configuration on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now`
    * **Policy**: `Configuration of wireless settings using Windows Connect Now` -> **Disabled**
  * **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars`
    * `EnableRegistrars` = `0` (REG_DWORD)
    * `DisableUPnPRegistrar` = `1` (REG_DWORD)
    * `DisableInBand802DOT11Registrar` = `1` (REG_DWORD)
    * `DisableFlashConfigRegistrar` = `1` (REG_DWORD)
    * `DisableWPDRegistrar` = `1` (REG_DWORD)

---

## Rationale
Windows Connect Now (WCN) provides mechanisms for wireless network configuration using Wi-Fi Protected Setup (WPS) protocols across various discovery media, including UPnP (Universal Plug and Play), In-Band 802.11, USB flash drives (FlashConfig), and Windows Portable Devices (WPD).

On Active Directory Domain Controllers:
1. **Tier 0 Dedicated Wired Infrastructure**: Domain Controllers must run on dedicated, physical wired server backbones within physically secured datacenter segments. Wireless configuration mechanisms have no legitimate place on these machines.
2. **UPnP and Wireless Exploitation**: UPnP registrars and in-band 802.11 discovery listening components can introduce local broadcast vulnerabilities, unauthenticated device registration attacks, or credential leakage over broadcast media.
3. **Attack Surface Elimination**: Setting `Configuration of wireless settings using Windows Connect Now` to `Disabled` ensures that all WCN registrars (UPnP, In-Band 802.11, FlashConfig, WPD) are explicitly turned off.

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Domain Controllers are managed via wired interfaces and do not use WCN wireless provisioning. Disabling WCN has zero impact on Active Directory replication, Kerberos, DNS, or server networking.
* **Hardware Profile**: Eliminates any automated attempt by Windows to discover or configure wireless access points or WPS-enabled routers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now`
4. Configure the policy:
   * **Setting**: `Configuration of wireless settings using Windows Connect Now`
   * **State**: **Disabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable WCN wireless settings configuration registrars on the Domain Controller.

[Download Script: Configure-DisableWcnWirelessConfig.ps1](../implementation_scripts/Configure-DisableWcnWirelessConfig.ps1)

```powershell
# Configure-DisableWcnWirelessConfig.ps1
# Description: Disables Windows Connect Now wireless settings configuration registrars on Domain Controllers.

Write-Host "Disabling Windows Connect Now Wireless Settings Configuration..." -ForegroundColor Cyan

$WcnRegsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
if (-not (Test-Path -Path $WcnRegsPath)) {
    New-Item -Path $WcnRegsPath -Force | Out-Null
}

Set-ItemProperty -Path $WcnRegsPath -Name "EnableRegistrars" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableUPnPRegistrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableInBand802DOT11Registrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableFlashConfigRegistrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableWPDRegistrar" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Windows Connect Now Wireless Settings Configuration disabled successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-WcnWirelessConfigStatus.ps1](../audit_scripts/Get-WcnWirelessConfigStatus.ps1)

```powershell
# Get-WcnWirelessConfigStatus.ps1
# Description: Audits registry configuration of Windows Connect Now registrars on Domain Controllers.

Write-Host "--- Auditing Windows Connect Now Wireless Settings Configuration Status ---" -ForegroundColor Cyan

$WcnRegsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
$Expected = @{
    "EnableRegistrars"               = 0
    "DisableUPnPRegistrar"           = 1
    "DisableInBand802DOT11Registrar" = 1
    "DisableFlashConfigRegistrar"    = 1
    "DisableWPDRegistrar"            = 1
}

$IsVulnerable = $false

if (Test-Path -Path $WcnRegsPath) {
    $Reg = Get-ItemProperty -Path $WcnRegsPath -ErrorAction SilentlyContinue
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
    Write-Host "    [!] WCN Registrars Registry Path NOT FOUND" -ForegroundColor Red
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
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.6.20.1 (Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled')
* **ANSSI AD Hardening Guide**: Baseline controls eliminating consumer wireless provisioning and UPnP interfaces on Tier 0 systems.
