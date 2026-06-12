# Hardening Requirement: Block Outbound Traffic for Known LOLBins

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security\Outbound Rules`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`

---

## Rationale
Malicious actors frequently abuse built-in Windows administrative utilities (known as Living Off the Land Binaries, or LOLBins) to download malicious payloads, exfiltrate sensitive data, and communicate with external command-and-control (C2) servers. Because these binaries are digitally signed by Microsoft and native to the operating system, they bypass traditional application control and endpoint detection solutions.

Blocking outbound network communication for binaries that have no legitimate business requirement to connect to external networks (such as `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `regsvr32.exe`, `rundll32.exe`, `cscript.exe`, `wscript.exe`, and `hh.exe`) significantly mitigates the risk of command-and-control communication and data exfiltration.

---

## Legacy Impact & Compatibility
* **Legitimate Scripts**: Administrative scripts, third-party software deployment installers, or internal software update tools that execute using `cscript.exe`, `wscript.exe`, or `mshta.exe` and require access to network shares or intranet servers will be blocked.
* **Testing Phase**: Prior to deployment across the entire active domain, organizations must perform audit-mode or scoped pilot-group testing to identify any line-of-business applications requiring exclusions for these binaries. If exclusions are necessary, they should be restricted to specific destination IP addresses, ports, or authorized AD user groups.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Configure outbound firewall rules under a Group Policy Object to block outbound traffic from the designated LOLBins.

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management workstation.
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security\Outbound Rules`
4. For each target LOLBin binary, create a new rule:
   * Right-click **Outbound Rules** and select **New Rule...**
   * **Rule Type**: `Program`
   * **Program**: Choose `This program path` and enter the path matching the binary (both x64 and x86 paths if applicable, e.g., `%SystemRoot%\System32\mshta.exe` and `%SystemRoot%\SysWOW64\mshta.exe`).
   * **Action**: `Block the connection`
   * **Profile**: Select `Domain`, `Private`, and `Public`.
   * **Name**: Specify a descriptive name (e.g., `Hardening: Block Outbound mshta.exe (x64)`).
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target client endpoints and member servers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the rules locally on standalone systems or during reference image build phases.

[Download Script: Configure-BlockLOLBinsOutbound.ps1](implementation_scripts/Configure-BlockLOLBinsOutbound.ps1)

```powershell
# Configure-BlockLOLBinsOutbound.ps1
# Description: Configures local outbound Windows Defender Firewall rules to block network connections from known LOLBins.

$Lolbins = @(
    @{ Name = "mshta.exe (x64)"; Path = "%SystemRoot%\System32\mshta.exe" },
    @{ Name = "mshta.exe (x86)"; Path = "%SystemRoot%\SysWOW64\mshta.exe" },
    @{ Name = "certutil.exe (x64)"; Path = "%SystemRoot%\System32\certutil.exe" },
    @{ Name = "certutil.exe (x86)"; Path = "%SystemRoot%\SysWOW64\certutil.exe" },
    @{ Name = "bitsadmin.exe (x64)"; Path = "%SystemRoot%\System32\bitsadmin.exe" },
    @{ Name = "bitsadmin.exe (x86)"; Path = "%SystemRoot%\SysWOW64\bitsadmin.exe" },
    @{ Name = "regsvr32.exe (x64)"; Path = "%SystemRoot%\System32\regsvr32.exe" },
    @{ Name = "regsvr32.exe (x86)"; Path = "%SystemRoot%\SysWOW64\regsvr32.exe" },
    @{ Name = "rundll32.exe (x64)"; Path = "%SystemRoot%\System32\rundll32.exe" },
    @{ Name = "rundll32.exe (x86)"; Path = "%SystemRoot%\SysWOW64\rundll32.exe" },
    @{ Name = "cscript.exe (x64)"; Path = "%SystemRoot%\System32\cscript.exe" },
    @{ Name = "cscript.exe (x86)"; Path = "%SystemRoot%\SysWOW64\cscript.exe" },
    @{ Name = "wscript.exe (x64)"; Path = "%SystemRoot%\System32\wscript.exe" },
    @{ Name = "wscript.exe (x86)"; Path = "%SystemRoot%\SysWOW64\wscript.exe" },
    @{ Name = "hh.exe (x64)"; Path = "%SystemRoot%\hh.exe" },
    @{ Name = "hh.exe (x86)"; Path = "%SystemRoot%\SysWOW64\hh.exe" }
)

Write-Host "Applying outbound firewall block rules for known LOLBins..." -ForegroundColor Cyan

foreach ($Bin in $Lolbins) {
    $DisplayName = "Hardening: Block Outbound $($Bin.Name)"
    $Existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -DisplayName $DisplayName `
            -Name $DisplayName `
            -Direction Outbound `
            -Action Block `
            -Program $Bin.Path `
            -Profile Any `
            -Enabled True | Out-Null
        Write-Host "[+] Outbound block rule created for $($Bin.Name)." -ForegroundColor Green
    } else {
        Set-NetFirewallRule -DisplayName $DisplayName -Action Block -Enabled True | Out-Null
        Write-Host "[~] Outbound block rule for $($Bin.Name) already exists, updated state to Enabled/Block." -ForegroundColor Gray
    }
}

Write-Host "Outbound firewall rules configured successfully." -ForegroundColor Green
```

*To verify the settings have been applied:*

[Download Script: Get-BlockedLOLBinsOutboundStatus.ps1](audit_scripts/Get-BlockedLOLBinsOutboundStatus.ps1)

```powershell
# Get-BlockedLOLBinsOutboundStatus.ps1
# Description: Audits the presence and configuration of outbound firewall rules blocking known LOLBins.

$Lolbins = @(
    @{ Name = "mshta.exe (x64)"; Path = "%SystemRoot%\System32\mshta.exe" },
    @{ Name = "mshta.exe (x86)"; Path = "%SystemRoot%\SysWOW64\mshta.exe" },
    @{ Name = "certutil.exe (x64)"; Path = "%SystemRoot%\System32\certutil.exe" },
    @{ Name = "certutil.exe (x86)"; Path = "%SystemRoot%\SysWOW64\certutil.exe" },
    @{ Name = "bitsadmin.exe (x64)"; Path = "%SystemRoot%\System32\bitsadmin.exe" },
    @{ Name = "bitsadmin.exe (x86)"; Path = "%SystemRoot%\SysWOW64\bitsadmin.exe" },
    @{ Name = "regsvr32.exe (x64)"; Path = "%SystemRoot%\System32\regsvr32.exe" },
    @{ Name = "regsvr32.exe (x86)"; Path = "%SystemRoot%\SysWOW64\regsvr32.exe" },
    @{ Name = "rundll32.exe (x64)"; Path = "%SystemRoot%\System32\rundll32.exe" },
    @{ Name = "rundll32.exe (x86)"; Path = "%SystemRoot%\SysWOW64\rundll32.exe" },
    @{ Name = "cscript.exe (x64)"; Path = "%SystemRoot%\System32\cscript.exe" },
    @{ Name = "cscript.exe (x86)"; Path = "%SystemRoot%\SysWOW64\cscript.exe" },
    @{ Name = "wscript.exe (x64)"; Path = "%SystemRoot%\System32\wscript.exe" },
    @{ Name = "wscript.exe (x86)"; Path = "%SystemRoot%\SysWOW64\wscript.exe" },
    @{ Name = "hh.exe (x64)"; Path = "%SystemRoot%\hh.exe" },
    @{ Name = "hh.exe (x86)"; Path = "%SystemRoot%\SysWOW64\hh.exe" }
)

Write-Host "Auditing outbound firewall rules for known LOLBins..." -ForegroundColor Cyan

$Vulnerable = $false

foreach ($Bin in $Lolbins) {
    $DisplayName = "Hardening: Block Outbound $($Bin.Name)"
    $Rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    $Color = "Red"
    
    if ($null -ne $Rule) {
        $ProgFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        $ProgPath = "None"
        if ($null -ne $ProgFilter) {
            $ProgPath = $ProgFilter.Program
        }
        
        if ($Rule.Enabled -eq $true -and $Rule.Direction -eq "Outbound" -and $Rule.Action -eq "Block" -and $ProgPath -eq $Bin.Path) {
            $Color = "Green"
            Write-Host "    - Firewall Rule: $($DisplayName) | Enabled: True | Action: Block | Program: $($ProgPath) (Compliant)" -ForegroundColor $Color
        } else {
            $Vulnerable = $true
            Write-Host "    - Firewall Rule: $($DisplayName) | Enabled: $($Rule.Enabled) | Action: $($Rule.Action) | Program: $($ProgPath) (Non-Compliant)" -ForegroundColor $Color
        }
    } else {
        $Vulnerable = $true
        Write-Host "    - Firewall Rule: $($DisplayName) | NOT FOUND (Non-Compliant)" -ForegroundColor $Color
    }
}

if ($Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R8 (Administration network subnets), Recommendation R19 (LDAP and name resolution security recommendations)
* **CIS Microsoft Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **CIS Microsoft Windows 10 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **Microsoft Learn**: Windows Defender Firewall with Advanced Security Design Guide
