# [REQ-PAW-189] Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention` = `0`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize` = `131072`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention` = `0`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize` = `1048576`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention` = `0`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize` = `32768`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention` = `0`
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize` = `131072`

---

## Rationale
Privileged Access Workstations (PAWs) serve as the dedicated management plane for Active Directory Domain Controllers, Tier 0 directory services, and critical identity infrastructure. Every interactive logon, administrative command execution, PowerShell script block, and remote management session initiated from a PAW carries severe security sensitivity.

Default event log capacities (20 MB) or legacy 192 MB baselines roll over rapidly during heavy administrative activity or forensic investigations, destroying vital attribution evidence. Expanding the **Security** log to **1 GB** (`1,048,576 KB`), **System** and **Application** logs to **128 MB** (`131,072 KB`), and **Setup** log to **32 MB** (`32,768 KB`) establishes a robust local forensic buffer that preserves audit trails across extended operational periods:

1. **High-Privilege Forensic Attribution**: Detailed auditing of administrative tooling (e.g., Active Directory Administrative Center, RSAT, PowerShell remoting, Mimikatz defense telemetry) generates voluminous Security event records. A 1 GB Security log ensures high-fidelity evidence preservation even if centralized log forwarding encounters temporary network partitions.
2. **64 KB Boundary Alignment**: The Windows Event Log service allocates and writes event records in 64 KB memory chunks. All configured sizes in KB must be integer multiples of 64 (`SizeKB % 64 == 0`). Non-aligned values will be automatically truncated or rounded by the operating system (`1,048,576 / 64 = 16,384`; `131,072 / 64 = 2,048`; `32,768 / 64 = 512`).
3. **Retention Policy**: Configuring retention behavior to "Overwrite events as needed" (GPO: `Disabled`, registry value `0`) ensures that new audit entries are never rejected or dropped when capacity is reached.
4. **Memory and I/O Impact**: Windows utilizes memory-mapped files (`.evtx`) for the Event Log service. Only actively accessed pages are mapped into virtual memory; larger file limits do not consume active physical RAM.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Allocates approximately 1.32 GB of maximum disk space in `%SystemRoot%\System32\Winevt\Logs`. Modern PAW hardware specifications easily absorb this footprint (representing less than 0.3% of total storage).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`131072` KB)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`1048576` KB)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`32768` KB)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`131072` KB)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtEventLogSizes.ps1](../implementation_scripts/Configure-PawAtEventLogSizes.ps1)

```powershell
#Configure-PawAtEventLogSizes.ps1
# Description: Configures Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs.

Write-Host "Configuring Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 131072 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 1048576 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 131072 -Type DWord -Force

Write-Host "[+] Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtEventLogSizesStatus.ps1](../audit_scripts/Get-PawAtEventLogSizesStatus.ps1)

```powershell
#Get-PawAtEventLogSizesStatus.ps1
# Description: Audits Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs.

Write-Host "--- Auditing Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName = "MaxSize"
$ExpectedValue = 131072
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure - Meets or exceeds threshold $($ExpectedValue))" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: >= $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: >= $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$ValueName = "MaxSize"
$ExpectedValue = 1048576
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure - Meets or exceeds threshold $($ExpectedValue))" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: >= $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: >= $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
$ValueName = "MaxSize"
$ExpectedValue = 32768
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure - Meets or exceeds threshold $($ExpectedValue))" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: >= $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: >= $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$ValueName = "MaxSize"
$ExpectedValue = 131072
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure - Meets or exceeds threshold $($ExpectedValue))" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: >= $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: >= $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
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
* **DoD Windows 10/11 Security Technical Implementation Guide (STIG)**: Rule SV-220707r879607_rule (Security Log MaxSize >= 1,024,000 KB), SV-220705r556754_rule (Application Log MaxSize >= 32,768 KB), SV-220709r556766_rule (System Log MaxSize >= 32,768 KB)
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.26.1.1, 18.10.26.1.2 (Application >= 32,768 KB), 18.10.26.2.1, 18.10.26.2.2 (Security >= 196,608 KB), 18.10.26.3.1, 18.10.26.3.2 (Setup >= 32,768 KB), 18.10.26.4.1, 18.10.26.4.2 (System >= 32,768 KB)
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions for Windows client platforms
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters and forensic preservation recommendations for Tier 0 administrative workstations

