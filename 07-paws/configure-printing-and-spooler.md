# [REQ-PAW-015] Configure Secure Printing and Print Spooler Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations.
* **Operating Systems**: Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **System Service GPO**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Print Spooler` -> Service Startup Mode: **Disabled**
  * **Point and Print GPO**: `Computer Configuration\Policies\Administrative Templates\Printers\Limits print driver installation to Administrators` -> Enabled
  * **Registry Location (Service)**: `HKLM\SYSTEM\CurrentControlSet\Services\Spooler` -> `Start` = `4` (REG_DWORD)
  * **Registry Location (Printers)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint` -> `RestrictDriverInstallationToAdministrators` = `1` (REG_DWORD)

---

## Rationale
The Windows Print Spooler service (`Spooler`) has been a recurring source of critical privilege escalation and coercion exploits (e.g., the PrintNightmare family). 

To secure Privileged Access Workstations (PAWs), which host highly privileged Tier 0 credentials:
1. **Disable the Print Spooler**: PAWs should never act as print servers or need print capabilities. Disabling the `Spooler` service completely eliminates this massive attack surface.
2. **Point and Print Restrictions**: As a defense-in-depth fallback, restricting print driver installations and updates to Administrators ensures that even if the spooler service is temporarily enabled for maintenance, standard users cannot load arbitrary, untrusted drivers.

---

## Legacy Impact & Compatibility
* **No Printing Support**: Printing from PAWs is completely disabled. This aligns with Tier 0 isolation principles where PAWs are restricted to administration and are not used for general office productivity.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Disable the Print Spooler Service
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO applied to your PAWs (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Double-click **Print Spooler**.
5. Check **Define this policy setting** and select **Disabled**. Click **OK**.

#### 2. Restrict Point and Print Driver Installations
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Printers`
2. Double-click **Limits print driver installation to Administrators**.
3. Set it to **Enabled** and click **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable the Print Spooler service and enforce driver restrictions.

[Download Script: Configure-PrintingAndSpooler.ps1](implementation_scripts/Configure-PrintingAndSpooler.ps1)

```powershell
# Configure-PrintingAndSpooler.ps1
# Description: Disables the Print Spooler service and configures Point and Print driver installation restrictions on the local PAW.

Write-Host "Hardening Print Spooler and Printer configurations for PAWs..." -ForegroundColor Cyan

# 1. Disable the Print Spooler Service
if (Get-Service -Name "Spooler" -ErrorAction SilentlyContinue) {
    Set-Service -Name "Spooler" -StartupType Disabled -Confirm:$false
    Stop-Service -Name "Spooler" -Force -Confirm:$false
    Write-Host "[+] Print Spooler service has been stopped and disabled." -ForegroundColor Green
} else {
    Write-Host "[+] Print Spooler service not found on local machine." -ForegroundColor Gray
}

# 2. Limit Print Driver Installation to Administrators (Defense-in-Depth)
$PrinterPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $PrinterPath)) {
    New-Item -Path $PrinterPath -Force | Out-Null
}
Set-ItemProperty -Path $PrinterPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Print driver installation restricted to Administrators." -ForegroundColor Green
```

*To audit these printer security configurations on the PAW:*

[Download Script: Get-PrintingAndSpoolerStatus.ps1](audit_scripts/Get-PrintingAndSpoolerStatus.ps1)

```powershell
# Get-PrintingAndSpoolerStatus.ps1
# Description: Audits print spooler status and Point and Print configurations on the local PAW.

Write-Host "--- Auditing PAW Secure Printing and Spooler Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit Spooler Service Startup Type
$Service = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    # Check StartupType
    $StartupType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'").StartMode
    # StartMode can be "Disabled", "Manual", "Auto"
    $Color = if ($StartupType -eq "Disabled") { "Green" } else { "Red" }
    Write-Host "  [-] Print Spooler Service Startup: $StartupType (Expected: Disabled)" -ForegroundColor $Color
    if ($StartupType -ne "Disabled") {
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [+] Print Spooler Service is not present on this machine." -ForegroundColor Green
}

# 2. Audit Point and Print Registry Restriction
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$Name = "RestrictDriverInstallationToAdministrators"
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

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark - Section 18.7 (Printing settings)
* **ANSSI AD Hardening Guide**: Section addressing system services minimization (disabling the Spooler service on sensitive systems).
