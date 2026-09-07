# [REQ-DC-151] Disable Link-Layer Topology Discovery Mapper I/O Driver on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery`
    * **Policy**: `Turn on Mapper I/O (LLTDIO) driver` -> **Disabled**
  * **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD`
    * `AllowLLTDIOOnDomain` = `0` (REG_DWORD)
    * `AllowLLTDIOOnPublicNet` = `0` (REG_DWORD)
    * `EnableLLTDIO` = `0` (REG_DWORD)
    * `ProhibitLLTDIOOnPrivateNet` = `0` (REG_DWORD)

---

## Rationale
The Link-Layer Topology Discovery (LLTD) Mapper I/O (LLTDIO) network protocol driver queries neighboring network hosts to discover physical network topology, bandwidth capabilities, and device characteristics for Windows network mapping tools.

On Tier 0 Domain Controllers:
1. **Attack Surface Minimization**: Domain Controllers must not act as network mapping query clients or probe neighboring devices. Running network discovery protocol drivers in kernel space introduces unnecessary attack surface.
2. **Reconnaissance Suppression**: Prohibiting LLTDIO driver activity ensures that the Domain Controller cannot be utilized to perform unauthorized local link-layer discovery queries across adjoining subnets.

Disabling the Mapper I/O driver (`Turn on Mapper I/O (LLTDIO) driver -> Disabled`) sets the registry flags under `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD` to `0`, ensuring the driver is completely disabled across domain, private, and public network profiles.

---

## Legacy Impact & Compatibility
* **Network Mapping**: Disabling the Mapper I/O driver prevents the Domain Controller from generating graphical network maps of neighboring systems in legacy Windows Network and Sharing Center views.
* **Core Functionality**: Active Directory replication, Kerberos authentication, SMB file shares (SYSVOL/NETLOGON), and administrative management tools (RSAT/WAC) do not rely on LLTDIO and operate unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery`
4. Configure the policy:
   * **Setting**: `Turn on Mapper I/O (LLTDIO) driver`
   * **State**: **Disabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable the LLTD Mapper I/O driver on the Domain Controller.

[Download Script: Configure-DisableLltdMapperIoDriver.ps1](../implementation_scripts/Configure-DisableLltdMapperIoDriver.ps1)

```powershell
# Configure-DisableLltdMapperIoDriver.ps1
# Description: Disables the LLTD Mapper I/O (LLTDIO) driver policy on Domain Controllers.

Write-Host "Disabling LLTD Mapper I/O (LLTDIO) Driver..." -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if (-not (Test-Path -Path $LltdPath)) {
    New-Item -Path $LltdPath -Force | Out-Null
}

Set-ItemProperty -Path $LltdPath -Name "AllowLLTDIOOnDomain" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "AllowLLTDIOOnPublicNet" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "EnableLLTDIO" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "ProhibitLLTDIOOnPrivateNet" -Value 0 -Type DWord -ErrorAction Stop

Write-Host "LLTD Mapper I/O Driver disabled successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-LltdMapperIoDriverStatus.ps1](../audit_scripts/Get-LltdMapperIoDriverStatus.ps1)

```powershell
# Get-LltdMapperIoDriverStatus.ps1
# Description: Audits registry configuration of LLTD Mapper I/O (LLTDIO) driver on Domain Controllers.

Write-Host "--- Auditing LLTD Mapper I/O Driver Status ---" -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
$Expected = @{
    "AllowLLTDIOOnDomain"        = 0
    "AllowLLTDIOOnPublicNet"     = 0
    "EnableLLTDIO"               = 0
    "ProhibitLLTDIOOnPrivateNet" = 0
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
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.6.9.1 (Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled')
* **ANSSI AD Hardening Guide**: Security guidelines to disable unnecessary link-layer discovery protocols and network interface drivers on Domain Controllers.
