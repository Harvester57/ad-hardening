# [REQ-ARCH-002] Restrict Administrative Management Protocols

## Target Scope
* **Applicable Systems**: Tier 0 assets (Domain Controllers, Jump Hosts) and Tier 1 member servers.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security

---

## Rationale
Remote management protocols like Remote Desktop Protocol (RDP) and Windows Remote Management (WinRM) are critical interfaces for directory administration. However, if these protocols are accessible from any host in the network, they become high-value targets for attackers.

If an attacker compromises a standard user workstation (Tier 2), they can run network scanners to identify all machines listening on port 3389 (RDP) or 5985/5986 (WinRM). They can then attempt password spraying or locate open administrative sessions. 

Restricting administrative protocols at the network and local firewall levels to allow inbound connections *only* from designated administrative jump hosts or PAW IP ranges stops lateral movement and brute-force attempts from standard user networks.

---

## Legacy Impact & Compatibility
* **Administration Location**: Administrators cannot manage Domain Controllers or member servers from standard client subnets. They must be physically connected to the dedicated administrative subnet or log on from a designated PAW.
* **Network Planning**: Any changes to administrative IP address ranges require updating GPO firewall rules. If IP assignments are incorrect, administrators can be locked out of remote management interfaces.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security`
4. Expand **Inbound Rules**.
5. Locate the rule **Remote Desktop - User Mode (TCP-In)** (or create a custom inbound port rule for TCP port 3389).
6. Double-click the rule, navigate to the **Scope** tab, and configure:
   * **Remote IP address**: Click **These IP addresses** and enter the specific IP range of the Tier 0 Jump Hosts and PAWs (e.g., `10.10.0.0/24`). Do not allow "Any IP address".
7. Locate the rule **Windows Remote Management (HTTP-In)** (TCP port 5985/5986).
8. Double-click the rule, navigate to the **Scope** tab, and enter the same administrative IP range under **Remote IP address**.
9. Enforce blocking of any other inbound connections by ensuring the default firewall action for the profile is set to block inbound connections that do not match an allow rule.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally on a Domain Controller or member server to create Windows Defender Firewall rules restricting WinRM and RDP to authorized subnets.

[Download Script: Set-AdminProtocolRestrictions.ps1](implementation_scripts/Set-AdminProtocolRestrictions.ps1)

```powershell
# Set-AdminProtocolRestrictions.ps1
# Creates inbound firewall rules to restrict RDP and WinRM to designated management subnets.

Write-Host "--- Restricting Administrative Protocols Inbound ---" -ForegroundColor Cyan

# Define the authorized administrative network subnet
$AdminSubnet = "10.10.0.0/24" # Replace with your PAW / Jump Host subnet

# 1. Restrict RDP (TCP port 3389) Inbound
$RdpRule = Get-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -ErrorAction SilentlyContinue
if ($RdpRule) {
    Write-Host "[+] Restricting existing RDP firewall rule to admin subnet..." -ForegroundColor Gray
    Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -RemoteAddress $AdminSubnet
    Write-Host "    RDP rule restricted." -ForegroundColor Green
} else {
    Write-Host "[+] Creating new restricted RDP inbound rule..." -ForegroundColor Gray
    New-NetFirewallRule -DisplayName "Hardening: Restricted RDP Inbound" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 3389 `
        -RemoteAddress $AdminSubnet `
        -Enabled True | Out-Null
    Write-Host "    Restricted RDP rule created." -ForegroundColor Green
}

# 2. Restrict WinRM HTTPS (TCP port 5986) Inbound
$WinRMRule = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -ErrorAction SilentlyContinue
if ($WinRMRule) {
    Write-Host "[+] Restricting existing WinRM HTTPS rule to admin subnet..." -ForegroundColor Gray
    Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -RemoteAddress $AdminSubnet
    Write-Host "    WinRM rule restricted." -ForegroundColor Green
} else {
    Write-Host "[+] Creating new restricted WinRM HTTPS inbound rule..." -ForegroundColor Gray
    New-NetFirewallRule -DisplayName "Hardening: Restricted WinRM HTTPS Inbound" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5986 `
        -RemoteAddress $AdminSubnet `
        -Enabled True | Out-Null
    Write-Host "    Restricted WinRM rule created." -ForegroundColor Green
}
```

*To audit the firewall restrictions:*
[Download Script: Test-AdminProtocolRestrictions.ps1](audit_scripts/Test-AdminProtocolRestrictions.ps1)

```powershell
# Test-AdminProtocolRestrictions.ps1
# Audits local firewall rules for RDP and WinRM to check remote address restrictions.

Write-Host "--- Auditing Administrative Port Firewall Rules ---" -ForegroundColor Cyan

$Rules = @(
    "Remote Desktop - User Mode (TCP-In)",
    "Windows Remote Management (HTTPS-In)",
    "Hardening: Restricted RDP Inbound",
    "Hardening: Restricted WinRM HTTPS Inbound"
)

foreach ($RuleName in $Rules) {
    $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($Rule) {
        $Address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule
        $color = if ($Address.RemoteAddress -ne "Any" -and $Address.RemoteAddress -ne "") { "Green" } else { "Red" }
        Write-Host "    - Firewall Rule: $($Rule.DisplayName) | Enabled: $($Rule.Enabled) | RemoteAddress Restriction: $($Address.RemoteAddress)" -ForegroundColor $color
    }
}
```

---

## 🔗 Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R8 (Dedicated management subnets and jump hosts)
* **CIS Microsoft Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall)
