# [REQ-DC-160] Configure Event Log Maximum File Sizes and Retention Policies on Domain Controllers

## Target Scope
* **Applicable Systems**: Active Directory Domain Controllers.
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Core Windows Event Log Channels (Administrative Templates)**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention` = `0`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize` = `131072` (128 MB)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention` = `0`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize` = `4194304` (4 GB)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention` = `0`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize` = `32768` (32 MB)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention` = `0`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize` = `262144` (256 MB)
  * **Active Directory Role-Specific Channels (Service Configuration)**:
    * `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service\Retention` = `0`
    * `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service\MaxSize` = `268435456` (256 MB in bytes)
    * `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\DNS Server\Retention` = `0`
    * `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\DNS Server\MaxSize` = `268435456` (256 MB in bytes)
    * `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication\Retention` = `0`
    * `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication\MaxSize` = `134217728` (128 MB in bytes)

---

## Rationale
Active Directory Domain Controllers are the highest-value targets (Tier 0) in an enterprise forest. In addition to serving as the central authentication authority, Domain Controllers continuously process authentication requests, Kerberos ticket issuances, directory service modifications, and directory replication. 

When comprehensive security audit policies are enforced on Domain Controllers (such as Kerberos Service Ticket operations [Event ID 4769], Account Logon events [Event ID 4768/4771], Directory Service Object Access [Event ID 4662], and Group Membership changes [Event ID 4728/4738]), Domain Controllers generate between 500 MB and multiple gigabytes of security telemetry daily.

Default event log capacities (20 MB for standard channels, 16 MB to 32 MB for role channels) roll over in a matter of minutes to hours during production load. This creates severe security vulnerabilities:
1. **Mitigation of Log-Flushing Attacks**: Adversaries executing high-frequency attacks (e.g., Kerberoasting, AS-REP Roasting, password spraying, or DCSync via `DsGetNCChanges`) frequently attempt to "flush" the Security log by generating floods of benign authentication or LDAP requests to overwrite compromise indicators before detection. Expanding the Security log to **4 GB** (`4,194,304 KB`) provides a resilient on-box buffer that retains weeks of forensic evidence even under heavy attack activity.
2. **Preservation of System and Replication Diagnostics**: Domain Controllers log extensive Netlogon, KDC, DNS, DFS Replication, and NTDS replication events into the **System**, **Directory Service**, **DNS Server**, and **DFS Replication** event channels. Allocating **256 MB** to System, Directory Service, and DNS Server logs prevents replication failures and tombstone synchronization issues from being overwritten during diagnostic troubleshooting.
3. **64 KB Boundary Alignment**: The Windows Event Log service allocates memory in 64 KB blocks. Configured sizes must be exact integer multiples of 64 (`SizeKB % 64 == 0`). Non-aligned values will be automatically truncated or rounded by the operating system (`4,194,304 / 64 = 65,536`; `262,144 / 64 = 4,096`; `131,072 / 64 = 2,048`; `32,768 / 64 = 512`).
4. **Retention Policy**: Enforcing retention method `0` (GPO: `Disabled` / Overwrite events as needed) guarantees that new security audits are continuously recorded rather than halted when log capacity is reached.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Allocates approximately 5.1 GB of maximum disk space in `%SystemRoot%\System32\Winevt\Logs`. Modern enterprise Domain Controller storage arrays (RAID 1/10 SSD or NVMe volumes with hundreds of gigabytes allocated to the system drive) easily accommodate this footprint without performance degradation.
* **Memory Utilization**: Windows utilizes memory-mapped files (`.evtx`) for the Event Log service. Only actively accessed pages are mapped into virtual memory; larger file limits do not consume active physical RAM.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the **Domain Controllers** Organizational Unit (e.g., `GPO_Hardening_DomainControllers`).
3. Configure the core Event Log Administrative Template policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`131072` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`4194304` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`32768` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`262144` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`

4. Configure Active Directory role-specific channels via Group Policy Preferences (Registry):
* Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
  * Add **Registry Item**:
    * Action: `Update`
    * Hive: `HKEY_LOCAL_MACHINE`
    * Key Path: `SYSTEM\CurrentControlSet\Services\EventLog\Directory Service`
    * Value Name: `MaxSize`
    * Value Type: `REG_DWORD`
    * Value Data: `268435456` (Decimal)
  * Add **Registry Item**:
    * Action: `Update`
    * Hive: `HKEY_LOCAL_MACHINE`
    * Key Path: `SYSTEM\CurrentControlSet\Services\EventLog\Directory Service`
    * Value Name: `Retention`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Decimal)
  * Add **Registry Item**:
    * Action: `Update`
    * Hive: `HKEY_LOCAL_MACHINE`
    * Key Path: `SYSTEM\CurrentControlSet\Services\EventLog\DNS Server`
    * Value Name: `MaxSize`
    * Value Type: `REG_DWORD`
    * Value Data: `268435456` (Decimal)
  * Add **Registry Item**:
    * Action: `Update`
    * Hive: `HKEY_LOCAL_MACHINE`
    * Key Path: `SYSTEM\CurrentControlSet\Services\EventLog\DNS Server`
    * Value Name: `Retention`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Decimal)
  * Add **Registry Item**:
    * Action: `Update`
    * Hive: `HKEY_LOCAL_MACHINE`
    * Key Path: `SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication`
    * Value Name: `MaxSize`
    * Value Type: `REG_DWORD`
    * Value Data: `134217728` (Decimal)
  * Add **Registry Item**:
    * Action: `Update`
    * Hive: `HKEY_LOCAL_MACHINE`
    * Key Path: `SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication`
    * Value Name: `Retention`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Decimal)

5. Link the GPO to the Domain Controllers OU and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally on Domain Controllers to configure the event log maximum sizes and retention policies:

[Download Script: Configure-DcEventLogSizes.ps1](implementation_scripts/Configure-DcEventLogSizes.ps1)

```powershell
#Configure-DcEventLogSizes.ps1
# Description: Configures Event Log Maximum File Sizes and Retention Policies on Domain Controllers.

Write-Host "Configuring Event Log Maximum File Sizes and Retention Policies on Domain Controllers..." -ForegroundColor Cyan

# 1. Core Channels via Policy Registry Branch (values in KB)
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 131072 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 4194304 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 262144 -Type DWord -Force

# 2. Active Directory Role Channels via Service Registry Branch (values in bytes)
$RoleChannels = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service"; MaxSizeBytes = 268435456 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DNS Server"; MaxSizeBytes = 268435456 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication"; MaxSizeBytes = 134217728 }
)

foreach ($Channel in $RoleChannels) {
    if (Test-Path -Path $Channel.Path) {
        Set-ItemProperty -Path $Channel.Path -Name "Retention" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $Channel.Path -Name "MaxSize" -Value $Channel.MaxSizeBytes -Type DWord -Force
        Write-Host "  [+] Configured $($Channel.Path) MaxSize to $($Channel.MaxSizeBytes) bytes" -ForegroundColor Green
    }
}

Write-Host "[+] Domain Controller Event Log Maximum File Sizes and Retention Policies applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-DcEventLogSizesStatus.ps1](audit_scripts/Get-DcEventLogSizesStatus.ps1)

```powershell
#Get-DcEventLogSizesStatus.ps1
# Description: Audits Event Log Maximum File Sizes and Retention Policies on Domain Controllers.

Write-Host "--- Auditing Domain Controller Event Log Maximum File Sizes and Retention Policies ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Application Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] Application $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Application $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Application $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 131072
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] Application $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Application $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Application $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit Security Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] Security $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Security $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Security $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 4194304
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] Security $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Security $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Security $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 3. Audit Setup Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] Setup $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Setup $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Setup $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 32768
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] Setup $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Setup $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Setup $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 4. Audit System Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] System $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: System $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: System $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 262144
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] System $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: System $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: System $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 5. Audit Role-Specific Channels (Directory Service, DNS Server, DFS Replication)
$RoleAudit = @(
    @{ Name = "Directory Service"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service"; MinBytes = 268435456 },
    @{ Name = "DNS Server"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DNS Server"; MinBytes = 268435456 },
    @{ Name = "DFS Replication"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication"; MinBytes = 134217728 }
)

foreach ($Item in $RoleAudit) {
    if (Test-Path -Path $Item.Path) {
        $Prop = Get-ItemProperty -Path $Item.Path -ErrorAction SilentlyContinue
        if ($null -ne $Prop) {
            $ActualSize = $Prop.MaxSize
            $ActualRetention = $Prop.Retention
            
            if ($null -ne $ActualRetention -and $ActualRetention -eq 0) {
                Write-Host "  [+] $($Item.Name) Retention = $($ActualRetention) (Secure)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: $($Item.Name) Retention = $($ActualRetention) (Expected: 0)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
            
            if ($null -ne $ActualSize -and [int64]$ActualSize -ge [int64]$Item.MinBytes) {
                Write-Host "  [+] $($Item.Name) MaxSize = $($ActualSize) bytes (Secure - Meets or exceeds threshold $($Item.MinBytes) bytes)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: $($Item.Name) MaxSize = $($ActualSize) bytes (Expected: >= $($Item.MinBytes) bytes)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        }
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **DoD Windows Server Domain Controller Security Technical Implementation Guide (STIG)**: Rule SV-205713r856754_rule (WN16-DC-000030 / WN19-DC-000030 / WN22-DC-000030: Security Log size >= 1,024,000 KB; enterprise DC recommendation >= 4 GB)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark: Section 18.10.26.1.1, 18.10.26.1.2 (Application >= 32,768 KB), 18.10.26.2.1, 18.10.26.2.2 (Security >= 196,608 KB), 18.10.26.3.1, 18.10.26.3.2 (Setup >= 32,768 KB), 18.10.26.4.1, 18.10.26.4.2 (System >= 32,768 KB)
* **Microsoft Security Guidance**: Active Directory Domain Services Audit and Logging Recommendations for Enterprise Environments
* **ANSSI Active Directory Hardening Guide**: Recommendation R52 and event logging retention strategies for Domain Controllers
