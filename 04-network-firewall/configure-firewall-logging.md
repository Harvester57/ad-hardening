# Hardening Requirement: Configure Firewall Logging and Operational Settings

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
Windows Defender Firewall with Advanced Security (WFAS) serves as the host-level stateful firewall protecting Active Directory resources from unauthorized network access. However, without correct logging and behavioral configuration, the firewall does not provide adequate defensive or diagnostic value:

1. **Visibility Gaps**: By default, Windows Defender Firewall does not log dropped packets. If logging is disabled, security administrators cannot detect failed connection attempts, reconnaissance scans (port scanning), or unauthorized network communications.
2. **Log Rotational Coverage**: The default firewall log size limit of 4096 KB (4 MB) is insufficient for enterprise environments. High volumes of traffic or network scanning will cause the log to roll over rapidly, destroying valuable historical entries needed for security audits and incident investigation.
3. **Deterministic Administrative Control**: Allowing local administrators to create local rules or local connection security rules (IPsec) on critical Tier 0 systems, such as Domain Controllers, risks bypassing centrally defined domain firewall GPOs. Restricting rule merging ensures a uniform security baseline.
4. **Behavioral Notification Control**: Disabling interactive firewall notifications prevents desktop alerts from prompting administrative users, reducing operational noise and social engineering opportunities.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Enabling logging of blocked packets carries negligible CPU and disk I/O overhead on modern storage hardware. Successful connections must not be logged in production, as doing so can trigger disk performance degradation due to logging high-volume network flows.
* **Local Rule Merging on Domain Controllers**: Setting "Apply local firewall rules" to "No" on Domain Controllers will cause the system to ignore any firewall rules created locally (e.g., via the local netsh, PowerShell, or third-party installers). All required inbound ports for application operations must be centrally managed and distributed via Group Policy.
* **Administrative Subnet Access**: If the default inbound action is set to block, all legitimate management traffic (such as RDP, WinRM, or SNMP) must have explicit inbound allow rules defined prior to deployment to prevent lockouts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_Firewall_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security`
4. Right-click **Windows Defender Firewall with Advanced Security** and select **Properties**.
5. Under the **Domain Profile** tab, configure the following settings:
   * **State**: `On (recommended)`
   * **Inbound connections**: `Block (default)`
   * **Outbound connections**: `Allow (default)`
   * Under **Settings**, click **Customize...**:
     * **Display a notification**: `No`
     * **Allow unicast response**: `Yes`
     * **Apply local firewall rules**: `No` (Set to `No` for Domain Controllers GPOs; set to `Yes` or `No` for Member Servers/Workstations depending on operational requirements)
     * **Apply local connection security rules**: `No` (Set to `No` for Domain Controllers GPOs; set to `Yes` or `No` for Member Servers/Workstations depending on operational requirements)
     * Click **OK**.
   * Under **Logging**, click **Customize...**:
     * **Name**: `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`
     * **Size limit (KB)**: `32768`
     * **Log dropped packets**: `Yes`
     * **Log successful connections**: `No`
     * Click **OK**.
6. Repeat the exact configuration steps (Step 5) for the **Private Profile** and **Public Profile** tabs.
7. Click **Apply** and then click **OK**.
8. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing or standalone systems) or if the control is not manageable via standard GPO GUI interfaces.

```powershell
# Set-FirewallLoggingAndSettings.ps1
# Description: Configures Windows Defender Firewall settings, log size, and log permissions for all profiles.

Write-Host "Applying Windows Defender Firewall hardening settings..." -ForegroundColor Cyan

# 1. Detect if the local system is a Domain Controller (ProductType = 2 is Domain Controller)
$IsDomainController = $false
$OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -ne $OSInfo) {
    if ($OSInfo.ProductType -eq 2) {
        $IsDomainController = $true
    }
}

# 2. Configure Domain, Private, and Public profiles
$Profiles = @("Domain", "Private", "Public")

foreach ($Profile in $Profiles) {
    Write-Host "Configuring Profile: $($Profile)..." -ForegroundColor Cyan
    
    # Enable firewall and set default inbound/outbound behavior and notifications
    Set-NetFirewallProfile -Profile $Profile `
                           -Enabled True `
                           -DefaultInboundAction Block `
                           -DefaultOutboundAction Allow `
                           -NotifyOnListen False `
                           -AllowUnicastResponseToMulticast True | Out-Null
                           
    # Configure logging: log dropped packets, disable successful logs, set size to 32MB (32768 KB)
    Set-NetFirewallProfile -Profile $Profile `
                           -LogBlocked True `
                           -LogAllowed False `
                           -LogMaxSizeKilobytes 32768 `
                           -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" | Out-Null
                           
    # Disable local rule merging only on Domain Controllers to prevent bypasses
    if ($IsDomainController) {
        Set-NetFirewallProfile -Profile $Profile `
                               -AllowLocalFirewallRules False `
                               -AllowLocalIPsecRules False | Out-Null
        Write-Host "Disabled local rule merging on DC for profile: $($Profile)" -ForegroundColor Green
    } else {
        Set-NetFirewallProfile -Profile $Profile `
                               -AllowLocalFirewallRules True `
                               -AllowLocalIPsecRules True | Out-Null
        Write-Host "Configured profile: $($Profile) with local rule merging allowed" -ForegroundColor Green
    }
}

Write-Host "Firewall logging and operational settings configuration completed successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*
```powershell
# Check current configuration state
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogBlocked, LogAllowed, LogMaxSizeKilobytes, LogFileName, AllowLocalFirewallRules, AllowLocalIPsecRules
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (Filtering and IPsec on Domain Controllers), Recommendation R8 (Administration network subnets / filtering rules)
* **CIS Windows Server 2016 Benchmark**: Section 19.1 (Domain Profile), Section 19.2 (Private Profile), Section 19.3 (Public Profile)
* **Microsoft Security Baseline Focus**: Windows Defender Firewall with Advanced Security settings
