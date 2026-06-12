# Hardening Requirement: Configure Workstation and Server Isolation

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security`

---

## Rationale
Once an adversary establishes initial access on a Tier 2 client workstation or a Member Server, they will attempt to move laterally across the network to identify high-value targets, harvest credentials, and locate Tier 0 administrative pathways.

Lateral movement commonly relies on standard management and remote connection protocols, including SMB (TCP 445), RPC (TCP 135 and dynamic ports), RDP (TCP 3389), and WinRM (TCP 5985/5986). In a standard enterprise design, workstations do not require inbound connections from other workstations, and member servers rarely require inbound connections from peer member servers in the same tier.

Configuring local firewalls via Group Policy to explicitly block inbound SMB, RPC, RDP, and WinRM traffic originating from peer subnets (while maintaining administrative exceptions from authorized management subnets and Domain Controllers) stops host-to-host lateral propagation and containment is maintained.

---

## Legacy Impact & Compatibility
* **Peer-to-Peer Sharing**: Local network resource sharing (such as peer-to-peer file folders, local network printer sharing, or remote system diagnostics) will fail.
* **Administrative Jump Hosts**: System administrators must use designated Privileged Access Workstations (PAWs) or Management Jump Hosts located in the allowed administrative subnets to manage these systems.
* **Application Clustered Services**: Member servers configured in clusters or running distributed applications that require peer-to-peer communication will require explicit, highly restricted exclusions to permit replication and synchronization ports.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Configure Peer Isolation GPO Rules
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstation_Isolation`) or Member Servers OU.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security`
4. Under **Inbound Rules**, create new custom rules to block peer traffic:
   * **Rule 1: Block Inbound SMB from Peers**:
     * **Action**: `Block the connection`
     * **Protocol**: `TCP` | **Local Port**: `445`
     * **Remote Address**: `[Insert Local Client / Peer Subnets, e.g., 10.20.0.0/16]`
     * **Profile**: `Domain, Private`
   * **Rule 2: Block Inbound RDP from Peers**:
     * **Action**: `Block the connection`
     * **Protocol**: `TCP` | **Local Port**: `3389`
     * **Remote Address**: `[Insert Local Client / Peer Subnets]`
     * **Profile**: `Domain, Private`
   * **Rule 3: Block Inbound WinRM from Peers**:
     * **Action**: `Block the connection`
     * **Protocol**: `TCP` | **Local Port**: `5985, 5986`
     * **Remote Address**: `[Insert Local Client / Peer Subnets]`
     * **Profile**: `Domain, Private`
   * **Rule 4: Block Inbound RPC from Peers**:
     * **Action**: `Block the connection`
     * **Protocol**: `TCP` | **Local Port**: `135, 49152-65535`
     * **Remote Address**: `[Insert Local Client / Peer Subnets]`
     * **Profile**: `Domain, Private`

#### 2. Create Management Allow Exceptions
In the same GPO, ensure there are priority inbound **Allow** rules configured to permit administration from dedicated administrative paths:
* **Allow Inbound Administration**:
  * **Action**: `Allow the connection`
  * **Protocol**: `TCP` | **Local Port**: `445, 3389, 5985, 5986`
  * **Remote Address**: `[Insert Administrative Subnet (PAW / Jump Hosts), e.g., 10.10.0.0/24]`
  * **Profile**: `Domain`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and apply workstation/server isolation rules.

#### Remediation Script:
[Download Script: Set-WorkstationIsolation.ps1](implementation_scripts/Set-WorkstationIsolation.ps1)

```powershell
# Set-WorkstationIsolation.ps1
# Configures local firewall rules to block inbound SMB, RPC, and RDP from peer subnets.
# Allows access only from designated Domain Controller and Admin Management subnets.

# Adjust subnets for your local environment
$AdminSubnet = "10.10.0.0/24"      # PAW / Jump Host / DC Subnet
$PeerSubnet = "10.20.0.0/16"       # Local client/member peer subnet

Write-Host "Applying Workstation and Server Isolation Firewall Rules..." -ForegroundColor Cyan

# 1. Enable firewall profiles
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
Write-Host "All firewall profiles enabled." -ForegroundColor Green

# 2. Block Inbound SMB (TCP 445) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound SMB from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 445 `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "SMB peer blocking rule created." -ForegroundColor Green

# 3. Block Inbound RDP (TCP 3389) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound RDP from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "RDP peer blocking rule created." -ForegroundColor Green

# 4. Block Inbound WinRM (TCP 5985, 5986) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound WinRM from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort @(5985, 5986) `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "WinRM peer blocking rule created." -ForegroundColor Green

# 5. Block Inbound RPC (TCP 135) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound RPC Mapper from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 135 `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "RPC Endpoint Mapper peer blocking rule created." -ForegroundColor Green

# 6. Allow Inbound Administration from Management Subnet (RDP, WinRM, SMB)
New-NetFirewallRule -DisplayName "Hardening: Allow Admin Management Inbound" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort @(445, 3389, 5985, 5986) `
    -RemoteAddress $AdminSubnet `
    -Profile Domain `
    -Enabled True | Out-Null
Write-Host "Management subnet inbound allowance rule created." -ForegroundColor Green

Write-Host "Workstation and Server isolation firewall rules applied successfully." -ForegroundColor Cyan
```

#### Audit Script:
[Download Script: Test-WorkstationIsolation.ps1](audit_scripts/Test-WorkstationIsolation.ps1)

```powershell
# Test-WorkstationIsolation.ps1
# Audits the presence of isolation blocking rules on local firewall profiles.

Write-Host "Auditing workstation and server peer isolation rules..." -ForegroundColor Cyan

$PortsToVerify = @(445, 3389, 135)
$FailedChecks = 0

foreach ($Port in $PortsToVerify) {
    # Query rules that block inbound traffic on specified ports
    $BlockRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.Direction -eq "Inbound" -and
        $_.Action -eq "Block" -and
        $_.Enabled -eq $true
    }
    
    $HasPortBlock = $false
    foreach ($Rule in $BlockRules) {
        # Check filter associated with the rule to resolve local port
        $Filter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        if ($Filter -and $Filter.LocalPort -eq [string]$Port) {
            $HasPortBlock = $true
        }
    }
    
    if ($HasPortBlock) {
        Write-Host "    - Isolation block rule for Port $($Port): FOUND (Compliant)" -ForegroundColor Green
    } else {
        Write-Host "    - Isolation block rule for Port $($Port): NOT FOUND (Non-Compliant)" -ForegroundColor Red
        $FailedChecks++
    }
}

if ($FailedChecks -eq 0) {
    Write-Host "Audit Result: Peer isolation firewall rules are verified." -ForegroundColor Green
} else {
    Write-Warning "Audit Result: Missing peer isolation rules detected!"
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R8 (Administration network subnets)
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **CIS Windows 10 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
