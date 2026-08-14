# [REQ-END-174] Account Policy: SMB Client and Server Security Options for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword` = `0` (REG_DWORD, Send unencrypted password disabled)
    * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoDisconnect` = `15` (REG_DWORD, Idle disconnect time = 15 minutes)
    * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableForcedLogoff` = `1` (REG_DWORD, Disconnect clients when logon hours expire)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\ForceLogoffWhenHourExpire` = `1` (REG_DWORD, Force logoff when logon hours expire)
    * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionShares` = `@()` (REG_MULTI_SZ, Anonymous shares = None)

---

## Rationale
Securing SMB workstation and server parameters blocks cleartext credential disclosure and enforces session termination boundaries:
* **Block Plaintext Passwords (`EnablePlainTextPassword = 0`)**: Prevents the SMB redirector from transmitting unencrypted credentials across the network to rogue or third-party SMB servers.
* **Auto-Disconnect Idle Sessions (`AutoDisconnect = 15`)**: Automatically suspends dormant SMB sessions after 15 minutes, mitigating session hijacking over open network connections.
* **Logon Hours Enforcement (`EnableForcedLogoff = 1`, `ForceLogoffWhenHourExpire = 1`)**: Ensures that when defined user logon hours expire, active SMB sessions and network connections are forcefully disconnected.
* **Null Session Shares (`NullSessionShares = @()`)**: Prevents unauthenticated anonymous users from accessing any local network shares.

---

## Legacy Impact & Compatibility
* **Third-Party SMB**: Older NAS appliances requiring plain text SMB authentication will be blocked. Endpoints must communicate using authenticated, encrypted SMB.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Microsoft network client: Send unencrypted password to third-party SMB servers**: `Disabled`
   * **Microsoft network server: Amount of idle time required before suspending session**: `15` minutes
   * **Microsoft network server: Disconnect clients when logon hours expire**: `Enabled`
   * **Network security: Force logoff when logon hours expire**: `Enabled`
   * **Network access: Shares that can be accessed anonymously**: `None` (empty)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountSmbSecurity.ps1](../implementation_scripts/Configure-EndAccountSmbSecurity.ps1)

```powershell
# Configure-EndAccountSmbSecurity.ps1
Write-Host "Configuring Endpoint SMB client and server security options..." -ForegroundColor Cyan

# 1. LanmanWorkstation
$LanmanWorkPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path $LanmanWorkPath)) { New-Item -Path $LanmanWorkPath -Force | Out-Null }
Set-ItemProperty -Path $LanmanWorkPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord -Force

# 2. LanmanServer
$LanmanServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $LanmanServerPath)) { New-Item -Path $LanmanServerPath -Force | Out-Null }
Set-ItemProperty -Path $LanmanServerPath -Name "AutoDisconnect" -Value 15 -Type DWord -Force
Set-ItemProperty -Path $LanmanServerPath -Name "EnableForcedLogoff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LanmanServerPath -Name "NullSessionShares" -Value @() -Type MultiString -Force

# 3. Netlogon ForceLogoff
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path $NetlogonPath)) { New-Item -Path $NetlogonPath -Force | Out-Null }
Set-ItemProperty -Path $NetlogonPath -Name "ForceLogoffWhenHourExpire" -Value 1 -Type DWord -Force

Write-Host "SMB client and server security options applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountSmbSecurityStatus.ps1](../audit_scripts/Get-EndAccountSmbSecurityStatus.ps1)

```powershell
# Get-EndAccountSmbSecurityStatus.ps1
Write-Host "--- Auditing Endpoint SMB Client and Server Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LanmanWorkPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$LanmanServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

function Test-RegVal ($Path, $Name, $Expected) {
    $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal $LanmanWorkPath "EnablePlainTextPassword" 0
Test-RegVal $LanmanServerPath "AutoDisconnect" 15
Test-RegVal $LanmanServerPath "EnableForcedLogoff" 1
Test-RegVal $NetlogonPath "ForceLogoffWhenHourExpire" 1

$NullShares = (Get-ItemProperty -Path $LanmanServerPath -Name "NullSessionShares" -ErrorAction SilentlyContinue).NullSessionShares
if ($null -ne $NullShares -and $NullShares.Count -gt 0 -and $NullShares[0] -ne "") {
    Write-Host "    [!] VULNERABLE: NullSessionShares contains values: $($NullShares -join ', ')" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] NullSessionShares: None" -ForegroundColor Green
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.9.1 (AutoDisconnect), Section 2.3.9.4 (EnableForcedLogoff), Section 2.3.10.2 (EnablePlainTextPassword), Section 2.3.10.11 (NullSessionShares), Section 2.3.11.6 (ForceLogoffWhenHourExpire)
* **ANSSI AD Hardening Guide**: Recommendations on SMB network protocols and idle session termination
* **DoD Windows 11 Computer STIG v2r6**: SMB encryption and session timeout controls
