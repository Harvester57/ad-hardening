# Hardening Requirement: Configure Active Directory Port Matrix

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security`

---

## Rationale
Active Directory services require several ports to function, including DNS, Kerberos, LDAP, SMB, and RPC. If firewalls are not configured to restrict traffic to only these essential ports, adversaries can perform internal network scanning, identify open services, exploit vulnerabilities in unhardened services, or pivot across systems.

Restricting network communications to the minimum required AD Port Matrix ensures:
1. **Attack Surface Reduction**: Unused services are blocked from receiving network connections.
2. **Reconnaissance Mitigation**: Internal port scanning returns blocked states, slowing down discovery.
3. **Lateral Movement Containment**: Compromised endpoints cannot arbitrary query services on domain controllers or other member systems.

---

## Legacy Impact & Compatibility
* **Legacy Protocols**: Disabling NetBIOS ports (UDP 137/138, TCP 139) will break legacy name resolution and applications relying on NetBIOS API.
* **RPC Communication**: Dynamic RPC ranges must be synchronized between firewall rules and system settings. If firewalls restrict the RPC range but the operating system is not configured to bind RPC to that range, legitimate RPC traffic (like replication and group policy processing) will fail.
* **Application Dependency**: Member servers hosting multi-tier applications must have custom inbound firewall rules created for their specific application ports.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Enforce Default Inbound Block
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the target systems (e.g., `GPO_Hardening_Firewall_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security`
4. Right-click **Windows Defender Firewall with Advanced Security** and select **Properties**.
5. For the **Domain Profile**, **Private Profile**, and **Public Profile** tabs, set:
   * **State**: `On (recommended)`
   * **Inbound connections**: `Block (default)`
   * **Outbound connections**: `Allow (default)`

#### 2. Create Inbound Allow Rules for the AD Port Matrix (Domain Controllers GPO)
For GPOs targeting Domain Controllers, configure the following inbound rules under **Inbound Rules**:

| Protocol | Port | Source Subnet | Description |
| :--- | :--- | :--- | :--- |
| TCP / UDP | 53 | Any / Client Subnets | DNS Resolution |
| UDP | 123 | Any / Client Subnets | NTP Time Sync |
| TCP / UDP | 88 | Any / Client Subnets | Kerberos Authentication |
| TCP / UDP | 464 | Any / Client Subnets | Kerberos Password Change |
| TCP / UDP | 389 | Any / Client Subnets | LDAP Directory Queries |
| TCP | 636 | Any / Client Subnets | LDAPS (Secure LDAP) |
| TCP | 3268 | Any / Client Subnets | Global Catalog Query |
| TCP | 3269 | Any / Client Subnets | Global Catalog SSL |
| TCP | 135 | Any / Client Subnets | RPC Endpoint Mapper |
| TCP | 445 | Any / Client Subnets | SMB (SYSVOL / GPO) |
| TCP | 49152-65535 | Any / Client Subnets | RPC Dynamic Ports (Replication / DFSR) |
| TCP | 3389 | PAW / Jump Host Subnets | RDP (Management) |
| TCP | 5985 / 5986 | PAW / Jump Host Subnets | WinRM (Management) |

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure the firewall profiles and inbound port rules.

#### Remediation Script:
```powershell
# Set-ADPortMatrixRules.ps1
# Configures local Windows Defender Firewall profiles and applies basic AD port matrix baseline rules.

Write-Host "Applying network firewall baseline policies..." -ForegroundColor Cyan

# 1. Enable firewall and set default block inbound
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Host "Firewall profiles enabled with Default Inbound Block." -ForegroundColor Green

# 2. Configure AD Port Matrix inbound rules (for local system role validation)
# Allow critical outbound by default, construct rules for inbound
$Rules = @(
    @{ Name = "AD-DNS-TCP"; Port = 53; Proto = "TCP" },
    @{ Name = "AD-DNS-UDP"; Port = 53; Proto = "UDP" },
    @{ Name = "AD-Kerberos-TCP"; Port = 88; Proto = "TCP" },
    @{ Name = "AD-Kerberos-UDP"; Port = 88; Proto = "UDP" },
    @{ Name = "AD-NTP-UDP"; Port = 123; Proto = "UDP" },
    @{ Name = "AD-RPC-Mapper-TCP"; Port = 135; Proto = "TCP" },
    @{ Name = "AD-LDAP-TCP"; Port = 389; Proto = "TCP" },
    @{ Name = "AD-LDAP-UDP"; Port = 389; Proto = "UDP" },
    @{ Name = "AD-SMB-TCP"; Port = 445; Proto = "TCP" },
    @{ Name = "AD-Kpwd-TCP"; Port = 464; Proto = "TCP" },
    @{ Name = "AD-Kpwd-UDP"; Port = 464; Proto = "UDP" },
    @{ Name = "AD-LDAPS-TCP"; Port = 636; Proto = "TCP" },
    @{ Name = "AD-GC-TCP"; Port = 3268; Proto = "TCP" },
    @{ Name = "AD-GC-SSL-TCP"; Port = 3269; Proto = "TCP" }
)

foreach ($Rule in $Rules) {
    $Name = $Rule.Name
    $Port = $Rule.Port
    $Proto = $Rule.Proto
    
    $Existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -Name $Name -DisplayName $Name `
            -Direction Inbound `
            -Action Allow `
            -Protocol $Proto `
            -LocalPort $Port `
            -Profile Domain, Private `
            -Enabled True | Out-Null
        Write-Host "Inbound rule created: $($Name) on port $($Port) ($($Proto))" -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $Name -Enabled True -Action Allow | Out-Null
        Write-Host "Inbound rule verified: $($Name)" -ForegroundColor Gray
    }
}

Write-Host "Firewall port matrix configuration completed successfully." -ForegroundColor Cyan
```

#### Audit Script:
```powershell
# Test-ADPortMatrixRules.ps1
# Audits local firewall status and checks if default inbound traffic is blocked.

Write-Host "Auditing local network firewall status..." -ForegroundColor Cyan

# 1. Check Windows Defender Firewall State
$Profiles = Get-NetFirewallProfile
$AllProfilesSecure = $true

foreach ($Profile in $Profiles) {
    $Enabled = $Profile.Enabled
    $InAction = $Profile.DefaultInboundAction
    
    if ($Enabled -eq $true -and $InAction -eq "Block") {
        Write-Host "Profile: $($Profile.Name) | Enabled: True | InboundAction: Block" -ForegroundColor Green
    } else {
        Write-Host "Profile: $($Profile.Name) | Enabled: $($Enabled) | InboundAction: $($InAction) (INSECURE)" -ForegroundColor Red
        $AllProfilesSecure = $false
    }
}

if ($AllProfilesSecure) {
    Write-Host "Audit Result: Firewall state configuration is compliant." -ForegroundColor Green
} else {
    Write-Warning "Audit Result: Firewall profiles are not fully secured!"
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R8 (Administration network subnets)
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **Microsoft Security Baseline**: Domain Controller and Member Server Baselines
