# [REQ-DC-025] Configure Security Options for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers.
* **Operating Systems**: Windows Server 2016 and above.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: 
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Control\Lsa\SubmitQueue`
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\AllowVulnerableChannel`
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange`
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange`
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge`
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey`
    * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes`
    * `HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths\Machine`
    * `HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths\Machine`

---

## Rationale
Windows Security Options control critical security settings such as anonymous access to Named Pipes, remote access to the registry (winreg), and domain member secure channel parameters. Restricting these options prevents credential sniffing, service enumeration, and remote unauthorized inspection of local configurations.

Specifically, the following settings are configured to protect the Tier 0 administrative boundary:
1. **Server Operator Task Scheduling (`SubmitQueue`)**: Restricting Server Operators from scheduling tasks on Domain Controllers prevents privilege escalation and command execution pathways.
2. **Secure Channel Protection (`RequireStrongKey` / `AllowVulnerableChannel`)**: Restricting secure channels to strong session keys and blocking vulnerable connections mitigates coercion and impersonation attacks.
3. **Machine Password Change (`RefusePasswordChange` / `DisablePasswordChange` / `MaximumPasswordAge`)**: Ensuring domain members rotate machine account passwords at regular intervals prevents offline account hijacking while forcing the DC to process password changes correctly.
4. **Anonymous Named Pipe Restricting (`NullSessionPipes`)**: Setting NullSessionPipes to a minimum required list prevents anonymous callers from enumerating user SIDs or directories on Domain Controllers.
5. **Remote Registry Restrictions (`winreg` Exact Paths and Paths)**: Restricting remote WinReg operations prevents information disclosure and configuration scanning.

---

## Legacy Impact & Compatibility
* **Remote Management Tools**: Third-party remote monitoring or inventory systems that rely on remote registry scanning (WinReg) may fail. Configure these systems to authenticate using dedicated service accounts or verify they use modern APIs.
* **Anonymous Access**: Legacy applications attempting to query Named Pipes anonymously will be blocked. Ensure applications authenticate using standard domain credentials.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management workstation.
2. Edit the modular Domain Controllers GPO (e.g., `SEC_DomainControllers_Hardening`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies as specified:

| Policy Setting | Setting Value |
| :--- | :--- |
| **Domain controller: Allow server operators to schedule tasks** | `Disabled` |
| **Domain controller: Allow vulnerable Netlogon secure channel connections** | `Not Configured` |
| **Domain controller: Refuse machine account password changes** | `Disabled` |
| **Domain member: Disable machine account password changes** | `Disabled` |
| **Domain member: Maximum machine account password age** | `30` |
| **Domain member: Require strong (Windows 2000 or later) session key** | `Enabled` |
| **Network access: Named Pipes that can be accessed anonymously** | `netlogon`, `samr`, `lsarpc` |
| **Network access: Remotely accessible registry paths** | `System\CurrentControlSet\Control\ProductOptions`, `System\CurrentControlSet\Control\Server Applications`, `Software\Microsoft\Windows NT\CurrentVersion` |
| **Network access: Remotely accessible registry paths and sub-paths** | `System\CurrentControlSet\Control\Print\Printers`, `System\CurrentControlSet\Services\Eventlog`, `Software\Microsoft\OLAP Server`, `Software\Microsoft\Windows NT\CurrentVersion\Print`, `Software\Microsoft\Windows NT\CurrentVersion\Windows`, `System\CurrentControlSet\Control\ContentIndex`, `System\CurrentControlSet\Control\Terminal Server`, `System\CurrentControlSet\Control\Terminal Server\UserConfig`, `System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration`, `Software\Microsoft\Windows NT\CurrentVersion\Perflib`, `System\CurrentControlSet\Services\SysmonLog` |

5. Link the GPO to the appropriate Organizational Unit.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the registry configuration locally.

[Download Script: Configure-DCSecurityOptions.ps1](implementation_scripts/Configure-DCSecurityOptions.ps1)

```powershell
# Configure-DCSecurityOptions.ps1
# Description: Configures GPO Security Options registry keys for Domain Controllers.

Write-Host "Applying hardening requirement: Configure Security Options for Domain Controllers..." -ForegroundColor Cyan

# 1. Domain controller: Allow server operators to schedule tasks = Disabled (SubmitQueue = 0)
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "SubmitQueue" -Value 0 -Type DWord -Force
Write-Host "    Domain controller: Allow server operators to schedule tasks set to Disabled." -ForegroundColor Green

# 2. Domain controller: Allow vulnerable Netlogon secure channel connections = Not Configured / Explicitly Blocked
$NetlogonParamsPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path $NetlogonParamsPath)) {
    New-Item -Path $NetlogonParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $NetlogonParamsPath -Name "AllowVulnerableChannel" -Value 0 -Type DWord -Force
Write-Host "    Domain controller: Allow vulnerable Netlogon connections set to Disabled." -ForegroundColor Green

# 3. Domain controller: Refuse machine account password changes = Disabled
Set-ItemProperty -Path $NetlogonParamsPath -Name "RefusePasswordChange" -Value 0 -Type DWord -Force
Write-Host "    Domain controller: Refuse machine account password changes set to Disabled." -ForegroundColor Green

# 4. Domain member: Disable machine account password changes = Disabled
Set-ItemProperty -Path $NetlogonParamsPath -Name "DisablePasswordChange" -Value 0 -Type DWord -Force
Write-Host "    Domain member: Disable machine account password changes set to Disabled." -ForegroundColor Green

# 5. Domain member: Maximum machine account password age = 30
Set-ItemProperty -Path $NetlogonParamsPath -Name "MaximumPasswordAge" -Value 30 -Type DWord -Force
Write-Host "    Domain member: Maximum machine account password age set to 30." -ForegroundColor Green

# 6. Domain member: Require strong (Windows 2000 or later) session key = Enabled
Set-ItemProperty -Path $NetlogonParamsPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force
Write-Host "    Domain member: Require strong session key set to Enabled." -ForegroundColor Green

# 7. Network access: Named Pipes that can be accessed anonymously (netlogon, samr, lsarpc)
$LanmanServerParamsPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $LanmanServerParamsPath)) {
    New-Item -Path $LanmanServerParamsPath -Force | Out-Null
}
$NullSessionPipes = @("netlogon", "samr", "lsarpc")
Set-ItemProperty -Path $LanmanServerParamsPath -Name "NullSessionPipes" -Value $NullSessionPipes -Type MultiString -Force
Write-Host "    Network access: Named Pipes that can be accessed anonymously configured." -ForegroundColor Green

# 8. Network access: Remotely accessible registry paths
$WinregExactPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths"
if (-not (Test-Path $WinregExactPath)) {
    New-Item -Path $WinregExactPath -Force | Out-Null
}
$AllowedExactPaths = @(
    "System\CurrentControlSet\Control\ProductOptions",
    "System\CurrentControlSet\Control\Server Applications",
    "Software\Microsoft\Windows NT\CurrentVersion"
)
Set-ItemProperty -Path $WinregExactPath -Name "Machine" -Value $AllowedExactPaths -Type MultiString -Force
Write-Host "    Network access: Remotely accessible registry paths configured." -ForegroundColor Green

# 9. Network access: Remotely accessible registry paths and sub-paths
$WinregPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths"
if (-not (Test-Path $WinregPath)) {
    New-Item -Path $WinregPath -Force | Out-Null
}
$AllowedPaths = @(
    "System\CurrentControlSet\Control\Print\Printers",
    "System\CurrentControlSet\Services\Eventlog",
    "Software\Microsoft\OLAP Server",
    "Software\Microsoft\Windows NT\CurrentVersion\Print",
    "Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "System\CurrentControlSet\Control\ContentIndex",
    "System\CurrentControlSet\Control\Terminal Server",
    "System\CurrentControlSet\Control\Terminal Server\UserConfig",
    "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
    "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
    "System\CurrentControlSet\Services\SysmonLog"
)

# Optional AD CS or WINS sub-paths
$CertSvc = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
if ($null -ne $CertSvc) {
    $AllowedPaths += "System\CurrentControlSet\Services\CertSvc"
    Write-Host "    AD CS detected: adding CertSvc registry path." -ForegroundColor Gray
}
$WinsSvc = Get-Service -Name "WINS" -ErrorAction SilentlyContinue
if ($null -ne $WinsSvc) {
    $AllowedPaths += "System\CurrentControlSet\Services\WINS"
    Write-Host "    WINS detected: adding WINS registry path." -ForegroundColor Gray
}

Set-ItemProperty -Path $WinregPath -Name "Machine" -Value $AllowedPaths -Type MultiString -Force
Write-Host "    Network access: Remotely accessible registry paths and sub-paths configured." -ForegroundColor Green

Write-Host "Domain Controller Security Options configuration completed." -ForegroundColor Green
```

To audit local configurations, execute the following script:

[Download Script: Get-DCSecurityOptionsStatus.ps1](audit_scripts/Get-DCSecurityOptionsStatus.ps1)

```powershell
# Get-DCSecurityOptionsStatus.ps1
# Description: Audits GPO Security Options registry keys for Domain Controllers.

Write-Host "--- Auditing Domain Controller Security Options ---" -ForegroundColor Cyan
$vulnerable = $false

# Helper function to check DWORD value
function Test-DwordValue {
    param(
        [string]$Path,
        [string]$ValueName,
        [int]$ExpectedValue
    )
    $Val = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -eq $Val) {
        Write-Host "    [!] VULNERABLE: $($ValueName) under $($Path) is not configured." -ForegroundColor Red
        return $true
    }
    $ActualVal = $Val.$ValueName
    if ($ActualVal -ne $ExpectedValue) {
        Write-Host "    [!] VULNERABLE: $($ValueName) is set to $($ActualVal) (Expected: $($ExpectedValue))" -ForegroundColor Red
        return $true
    }
    Write-Host "    [+] $($ValueName) is set to $($ActualVal) (Compliant)." -ForegroundColor Green
    return $false
}

# 1. Domain controller: Allow server operators to schedule tasks (SubmitQueue = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -ValueName "SubmitQueue" -ExpectedValue 0) {
    $vulnerable = $true
}

# 2. Domain controller: Allow vulnerable Netlogon connections (AllowVulnerableChannel = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "AllowVulnerableChannel" -ExpectedValue 0) {
    $vulnerable = $true
}

# 3. Domain controller: Refuse machine account password changes (RefusePasswordChange = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "RefusePasswordChange" -ExpectedValue 0) {
    $vulnerable = $true
}

# 4. Domain member: Disable machine account password changes (DisablePasswordChange = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "DisablePasswordChange" -ExpectedValue 0) {
    $vulnerable = $true
}

# 5. Domain member: Maximum machine account password age (MaximumPasswordAge = 30)
$MaxAgeVal = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue
if ($null -eq $MaxAgeVal) {
    Write-Host "    [!] VULNERABLE: MaximumPasswordAge is not configured." -ForegroundColor Red
    $vulnerable = $true
} else {
    $ActualAge = $MaxAgeVal.MaximumPasswordAge
    if ($ActualAge -gt 30 -or $ActualAge -eq 0) {
        Write-Host "    [!] VULNERABLE: MaximumPasswordAge is $($ActualAge) (Expected: 30 or fewer, but not 0)" -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "    [+] MaximumPasswordAge is $($ActualAge) (Compliant)." -ForegroundColor Green
    }
}

# 6. Domain member: Require strong session key (RequireStrongKey = 1)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "RequireStrongKey" -ExpectedValue 1) {
    $vulnerable = $true
}

# Helper function to check MultiString value
function Test-MultiStringValue {
    param(
        [string]$Path,
        [string]$ValueName,
        [string[]]$ExpectedElements
    )
    $Val = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -eq $Val) {
        Write-Host "    [!] VULNERABLE: $($ValueName) under $($Path) is not configured." -ForegroundColor Red
        return $true
    }
    $ActualList = $Val.$ValueName
    $Missing = @()
    foreach ($E in $ExpectedElements) {
        $Found = $false
        foreach ($A in $ActualList) {
            if ($A.Trim().ToLower() -eq $E.ToLower()) {
                $Found = $true
                break
            }
        }
        if (-not $Found) {
            $Missing += $E
        }
    }
    if ($Missing.Count -gt 0) {
        Write-Host "    [!] VULNERABLE: $($ValueName) is missing elements: $($Missing -join ', ')" -ForegroundColor Red
        return $true
    }
    Write-Host "    [+] $($ValueName) contains all required elements (Compliant)." -ForegroundColor Green
    return $false
}

# 7. Network access: Named Pipes that can be accessed anonymously
$RequiredPipes = @("netlogon", "samr", "lsarpc")
if (Test-MultiStringValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "NullSessionPipes" -ExpectedElements $RequiredPipes) {
    $vulnerable = $true
}

# 8. Network access: Remotely accessible registry paths
$RequiredExactPaths = @(
    "System\CurrentControlSet\Control\ProductOptions",
    "System\CurrentControlSet\Control\Server Applications",
    "Software\Microsoft\Windows NT\CurrentVersion"
)
if (Test-MultiStringValue -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" -ValueName "Machine" -ExpectedElements $RequiredExactPaths) {
    $vulnerable = $true
}

# 9. Network access: Remotely accessible registry paths and sub-paths
$RequiredPaths = @(
    "System\CurrentControlSet\Control\Print\Printers",
    "System\CurrentControlSet\Services\Eventlog",
    "Software\Microsoft\OLAP Server",
    "Software\Microsoft\Windows NT\CurrentVersion\Print",
    "Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "System\CurrentControlSet\Control\ContentIndex",
    "System\CurrentControlSet\Control\Terminal Server",
    "System\CurrentControlSet\Control\Terminal Server\UserConfig",
    "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
    "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
    "System\CurrentControlSet\Services\SysmonLog"
)

# Optional AD CS or WINS sub-paths
$CertSvc = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
if ($null -ne $CertSvc) {
    $RequiredPaths += "System\CurrentControlSet\Services\CertSvc"
}
$WinsSvc = Get-Service -Name "WINS" -ErrorAction SilentlyContinue
if ($null -ne $WinsSvc) {
    $RequiredPaths += "System\CurrentControlSet\Services\WINS"
}

if (Test-MultiStringValue -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" -ValueName "Machine" -ExpectedElements $RequiredPaths) {
    $vulnerable = $true
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server 2016 Benchmark v2.0.0 - Section 2.3.5.1, Section 2.3.5.2, Section 2.3.5.5, Section 2.3.6.4, Section 2.3.6.5, Section 2.3.6.6, Section 2.3.10.6, Section 2.3.10.8, Section 2.3.10.9
* **ANSSI AD Hardening Guide**: Section on Active Directory configuration and secure channels
