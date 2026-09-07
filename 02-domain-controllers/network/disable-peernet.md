# [REQ-DC-153] Disable Microsoft Peer-to-Peer Networking Services on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Network\Microsoft Peer-to-Peer Networking Services`
    * **Policy**: `Turn off Microsoft Peer-to-Peer Networking Services` -> **Enabled**
  * **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Peernet`
    * `Disabled` = `1` (REG_DWORD)

---

## Rationale
Microsoft Peer-to-Peer Networking Services comprise technologies such as the Peer Name Resolution Protocol (PNRP), Peer Graphing, and Grouping. These services allow distributed applications and workstations to locate each other, publish identities in peer clouds, and exchange data directly without centralized servers.

On Active Directory Domain Controllers:
1. **Inappropriate Technology on Tier 0**: Domain Controllers are centralized identity authorities designed for hierarchical client-server communication. Peer-to-peer mechanisms are completely antithetical to Tier 0 security isolation.
2. **Untracked Communication Channels**: PNRP and peer networks establish autonomous, unmanaged communication channels that bypass traditional network inspection and create covert data exchange surfaces.
3. **Attack Surface Reduction**: Disabling Peernet services (`Disabled = 1`) eliminates the PNRP protocol stack and shuts down peer mesh discovery ports on Domain Controllers.

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Standard Windows Server roles, Active Directory Domain Services, replication, Group Policy, Kerberos, DNS, and administrative consoles (RSAT, PowerShell Remoting, WAC) do not use Peer-to-Peer services.
* **Applications**: Peer-to-peer collaboration tools (such as HomeGroup or consumer mesh applications) are blocked. Such software must never be installed on Domain Controllers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Microsoft Peer-to-Peer Networking Services`
4. Configure the policy:
   * **Setting**: `Turn off Microsoft Peer-to-Peer Networking Services`
   * **State**: **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Microsoft Peer-to-Peer Networking Services on the Domain Controller.

[Download Script: Configure-DisablePeernet.ps1](../implementation_scripts/Configure-DisablePeernet.ps1)

```powershell
# Configure-DisablePeernet.ps1
# Description: Disables Microsoft Peer-to-Peer Networking Services policy on Domain Controllers.

Write-Host "Disabling Microsoft Peer-to-Peer Networking Services..." -ForegroundColor Cyan

$PeernetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
if (-not (Test-Path -Path $PeernetPath)) {
    New-Item -Path $PeernetPath -Force | Out-Null
}

Set-ItemProperty -Path $PeernetPath -Name "Disabled" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Microsoft Peer-to-Peer Networking Services disabled successfully (Disabled = 1)." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-PeernetStatus.ps1](../audit_scripts/Get-PeernetStatus.ps1)

```powershell
# Get-PeernetStatus.ps1
# Description: Audits registry configuration of Microsoft Peer-to-Peer Networking Services on Domain Controllers.

Write-Host "--- Auditing Microsoft Peer-to-Peer Networking Services Status ---" -ForegroundColor Cyan

$PeernetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
$ExpectedValue = 1

if (Test-Path -Path $PeernetPath) {
    $Reg = Get-ItemProperty -Path $PeernetPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.Disabled

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] Peernet Disabled: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] Peernet Disabled: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] Peernet Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.6.10.1 (Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled')
* **ANSSI AD Hardening Guide**: Security recommendations to deactivate unnecessary peer networking protocols and unmanaged discovery services on Domain Controllers.
