# Hardening Requirement: Harden Virtualization Hosts for Domain Controllers

## Target Scope
* **Applicable Systems**: Virtualization Hosts (Hyper-V / VMware ESXi hosting Domain Controllers)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, VMware vSphere ESXi 6.7+

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Hypervisor Host Group Policies, Local Host Firewall Configuration, and Virtualization Management boundaries

---

## Rationale
In modern IT environments, Domain Controllers (DCs) are frequently virtualized. However, a virtualized DC is only as secure as the physical host and hypervisor running it. 

If a hypervisor hosting a DC is compromised, an attacker can:
1. **Harvest NTDS.dit Offline**: Copy the virtual hard disk file (VHDX/VMDK) of the running DC and extract all domain password hashes offline.
2. **Manipulate Memory**: Dump the guest DC's LSASS memory directly from the hypervisor console, exposing active Tier 0 administrator credentials.
3. **Inject Arbitrary Commands**: Use integration tools (like Hyper-V Integration Services or VMware Tools) to run code within the guest OS without authenticating.

To mitigate these risks:
* **Host Segregation**: Hypervisors hosting Tier 0 Domain Controllers must be dedicated exclusively to Tier 0 workloads. Lower-tier virtual machines (Tier 1/2) must never run on the same physical host clusters.
* **Administrative Isolation**: The virtualization hosts and management consoles (e.g., vCenter, Hyper-V Manager) must be managed exclusively by Tier 0 administrative accounts.
* **Virtual Machine Security**: Enable shielded VMs or VM encryption options to cryptographically lock the guest OS resources and protect virtual disks from unauthorized access.

---

## Legacy Impact & Compatibility
* **Infrastructure Cost**: Dedicating specific physical hardware hosts solely for Domain Controllers and other Tier 0 VMs reduces server hardware resource utilization, potentially increasing cost.
* **Management Disruption**: Standard virtualization administrators will lose the ability to manage the hosts running Domain Controllers, requiring a separate, dedicated administrative pool.

---

## Implementation Steps

### Option A: Manual Virtualization Host Isolation (Preferred)

1. Identify all physical hosts running virtualized Domain Controllers.
2. Move all non-Tier 0 virtual machines off these hosts using live migration (vMotion/Live Migration).
3. Place these hosts into a dedicated, isolated hypervisor cluster (e.g., `Cluster-Tier0`).
4. Reconfigure management permissions on the virtualization console:
   * Remove standard admin permissions from the cluster.
   * Restrict access rights exclusively to a dedicated Tier 0 virtualization administrator group.
5. Disable unnecessary virtual integration services in the VM settings:
   * In Hyper-V Manager, open DC VM Properties -> **Integration Services** -> Uncheck **Guest services** and **Time synchronization** (if relying on NTP domain hierarchy).

---

### Option B: PowerShell Host Configuration Auditing

Run the following script block on a Domain Controller to determine if it is virtualized, identify the hypervisor type, and audit key integration parameters.

[Download Script: Get-DcVirtualizationStatus.ps1](audit_scripts/Get-DcVirtualizationStatus.ps1)

```powershell
# Get-DcVirtualizationStatus.ps1
# Description: Audits the virtualization environment of the Domain Controller.

Write-Host "--- Auditing DC Virtualization Status ---" -ForegroundColor Cyan

# 1. Determine if running on physical or virtual hardware
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$Model = $ComputerSystem.Model
$Manufacturer = $ComputerSystem.Manufacturer

Write-Host "[*] Host Manufacturer: $($Manufacturer)" -ForegroundColor White
Write-Host "[*] System Model:       $($Model)" -ForegroundColor White

$IsVirtual = $false
$HypervisorType = "Unknown"

if ($Model -match "Virtual Machine|VMware|VirtualBox|Xen") {
    $IsVirtual = $true
    if ($Manufacturer -match "Microsoft") { $HypervisorType = "Hyper-V" }
    elseif ($Manufacturer -match "VMware") { $HypervisorType = "VMware ESXi" }
}

if ($IsVirtual) {
    Write-Host "[-] WARNING: Domain Controller is virtualized on $($HypervisorType)." -ForegroundColor Yellow
    Write-Host "    Ensure the underlying host is secured as a Tier 0 asset." -ForegroundColor Yellow
    
    # 2. Check VM integration service settings if Hyper-V guest
    if ($HypervisorType -eq "Hyper-V") {
        $IntegrationServices = Get-Service -Name "vm*" -ErrorAction SilentlyContinue
        if ($IntegrationServices) {
            Write-Host "    Integration Services detected:" -ForegroundColor White
            foreach ($Svc in $IntegrationServices) {
                Write-Host "    - $($Svc.Name): $($Svc.Status)" -ForegroundColor White
            }
        }
    }
} else {
    Write-Host "[+] Domain Controller is running on physical hardware (secure boundary)." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R47 (Risques relatifs aux infrastructures de virtualisation)
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 3.d (Page 23), Section 4.d (Page 27)
* **Microsoft Security Guidance**: Securing Domain Controllers Against Virtualization Attacks
* **CIS Benchmark**: Section 2.3.1.2 (Harden Hypervisor Access Control)
