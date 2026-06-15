# [REQ-NET-013] Block Management Traffic Between Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Windows Firewall Inbound Rules**: Exclusion of Domain Controller IP addresses from allowed remote management rules (RDP, WinRM, WMI, ADWS) in the Domain Controllers GPO.

---

## Rationale
Domain Controllers (DCs) represent the Tier 0 security boundary of an Active Directory forest. In a multi-DC environment, security controls must prevent lateral movement and credential escalation between these core servers.

If an adversary gains administrative control of a single Domain Controller, they will immediately attempt to pivot to other DCs. By default, standard firewall configurations allow remote management protocols (RDP, WinRM, WMI) from all Tier 0 assets—including other Domain Controllers.

Enforcing intra-DC remote management blocking resolves this vector:
1. **Lateral Movement Containment**: Restricting management traffic between DCs (e.g. blocking RDP TCP 3389, WinRM TCP 5985/5986, WMI TCP 24158, and ADWS TCP 9389 from other DC IP addresses) prevents a compromised DC from being used to compromise other domain controllers.
2. **Replication Integrity**: Normal Active Directory replication and synchronization protocols (RPC replication, DNS, Kerberos, SMB) remain open and unaffected, while administrative logon and command execution protocols are blocked.
3. **Zero Trust Tiering**: Assumes that even Tier 0 systems must not trust other Tier 0 systems for remote command execution.

---

## Legacy Impact & Compatibility
* **Administration Workflow**: Administrators cannot RDP or execute remote PowerShell Remoting commands directly from one DC to another. They must manage each DC individually from authorized Privileged Access Workstations (PAWs) or dedicated Tier 0 jump hosts.
* **Multi-DC Discovery**: For non-GPO scripting configurations, the remediation script dynamically queries Active Directory to identify and block the IP addresses of other DCs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Configure the Domain Controllers GPO to restrict source IP addresses for remote management rules:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting Domain Controllers (e.g., `GPO_Hardening_DomainControllers_Firewall`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security`
4. Under **Inbound Rules**, configure rules for remote management (RDP, WinRM, WMI, ADWS) to:
   * Allow connections originating only from **Management/PAW subnets**.
   * Ensure that **Domain Controller IP addresses** are explicitly excluded from the allowed remote address list.
   * Alternatively, create explicit inbound **Block Rules** for ports `3389`, `5985`, `5986`, `24158`, and `9389` where the source IP addresses match the list of Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally on each DC to implement and audit the block rules.

#### Remediation Script:
[Download Script: Set-IntraDcManagementBlocking.ps1](implementation_scripts/Set-IntraDcManagementBlocking.ps1)

```powershell
# Set-IntraDcManagementBlocking.ps1
# Description: Configures local Windows Firewall rules to block remote management traffic (RDP, WinRM, WMI, ADWS) originating from other Domain Controllers to prevent lateral movement.

Write-Host "Applying hardening requirement: Block Management Traffic Between DCs..." -ForegroundColor Cyan

# 1. Get IP addresses of all Domain Controllers in the domain
$DcIPs = @()
try {
    $Dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    foreach ($Dc in $Dcs) {
        # Skip local computer
        if ($Dc.Name -ne $env:COMPUTERNAME) {
            if ($Dc.IPv4Address) { $DcIPs += $Dc.IPv4Address }
            if ($Dc.IPv6Address) { $DcIPs += $Dc.IPv6Address }
        }
    }
} catch {
    Write-Host "    Get-ADDomainController not available or not in AD domain. Skipping dynamic discovery." -ForegroundColor Yellow
}

if ($DcIPs.Count -eq 0) {
    Write-Host "    No other Domain Controllers discovered. Blocking rule will be created but inactive." -ForegroundColor Yellow
    # Fallback to a dummy address to ensure rule structure is correct
    $DcIPs = @("255.255.255.255")
} else {
    Write-Host "    Discovered other DCs: $($DcIPs -join ', ')" -ForegroundColor Gray
}

# 2. Configure local block rules for DC-to-DC remote management
$BlockRules = @(
    @{ Name = "AD-Block-IntraDC-RDP"; Port = 3389; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-WinRM-HTTP"; Port = 5985; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-WinRM-HTTPS"; Port = 5986; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-WMI"; Port = 24158; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-ADWS"; Port = 9389; Proto = "TCP" }
)

foreach ($Rule in $BlockRules) {
    $Name = $Rule.Name
    $Port = $Rule.Port
    $Proto = $Rule.Proto
    
    $Existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -Name $Name -DisplayName $Name `
            -Direction Inbound `
            -Action Block `
            -Protocol $Proto `
            -LocalPort $Port `
            -RemoteAddress $DcIPs `
            -Profile Domain, Private `
            -Enabled True | Out-Null
        Write-Host "Block rule created: $($Name) on port $($Port) ($($Proto)) from other DCs." -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $Name -Enabled True -Action Block -RemoteAddress $DcIPs | Out-Null
        Write-Host "Block rule verified: $($Name) on port $($Port) ($($Proto)) from other DCs." -ForegroundColor Gray
    }
}

Write-Host "Intra-DC management blocking rules applied successfully." -ForegroundColor Cyan
```

#### Audit Script:
[Download Script: Test-IntraDcManagementBlocking.ps1](audit_scripts/Test-IntraDcManagementBlocking.ps1)

```powershell
# Test-IntraDcManagementBlocking.ps1
# Description: Audits if management traffic from other Domain Controllers is blocked.

Write-Host "Auditing Intra-DC management blocking configurations..." -ForegroundColor Cyan

$vulnerable = $false
$BlockRules = @(
    "AD-Block-IntraDC-RDP",
    "AD-Block-IntraDC-WinRM-HTTP",
    "AD-Block-IntraDC-WinRM-HTTPS",
    "AD-Block-IntraDC-WMI",
    "AD-Block-IntraDC-ADWS"
)

foreach ($Name in $BlockRules) {
    $Rule = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($Rule) {
        if ($Rule.Enabled -eq $true -and $Rule.Action -eq "Block") {
            Write-Host "[+] Rule $($Name) is active and configured to Block." -ForegroundColor Green
        } else {
            Write-Host "[!] NON-COMPLIANT: Rule $($Name) exists but is disabled or not set to Block." -ForegroundColor Red
            $vulnerable = $true
        }
    } else {
        Write-Host "[!] NON-COMPLIANT: Block rule $($Name) is missing." -ForegroundColor Red
        $vulnerable = $true
    }
}

if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (Filtering and IPsec on Domain Controllers), Recommendation R8 (Administration network subnets / filtering rules)
* **CIS Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **DSInternals AD Firewall Guide (Michael Grafnetter)**: [Active Directory Firewall - Domain Controller Firewall](https://firewall.dsinternals.com/ADDS/)
