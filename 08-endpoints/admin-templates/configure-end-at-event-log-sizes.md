# [REQ-END-200] Administrative Templates: Event Log Maximum File Sizes and Retention Policies

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service
* **Policy Settings**:
  * Application: Specify the maximum log file size (KB) & Control Event Log behavior when the log file reaches its maximum size
  * Security: Specify the maximum log file size (KB) & Control Event Log behavior when the log file reaches its maximum size
  * Setup: Specify the maximum log file size (KB) & Control Event Log behavior when the log file reaches its maximum size
  * System: Specify the maximum log file size (KB) & Control Event Log behavior when the log file reaches its maximum size
* **Supported On**: Windows 10 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize` = `131072` (REG_DWORD, 128 MB)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention` = `"0"` (REG_SZ, Overwrite as needed)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize` = `1048576` (REG_DWORD, 1 GB)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention` = `"0"` (REG_SZ, Overwrite as needed)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize` = `32768` (REG_DWORD, 32 MB)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention` = `"0"` (REG_SZ, Overwrite as needed)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize` = `131072` (REG_DWORD, 128 MB)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention` = `"0"` (REG_SZ, Overwrite as needed)
* **Vulnerability References**: MITRE ATT&CK: T1070.001 (Indicator Removal on Host: Clear Windows Event Logs), T1562.002 (Impair Defenses: Disable Windows Event Logging)

---

## Rationale

Default Windows event log capacities (typically 20 MB) rollover within hours during normal workstation activity, and can be completely overwritten within minutes during active security incidents, brute-force attempts, or high-volume administrative operations. 

In hardened environments enforcing comprehensive audit policies (such as Process Creation with command-line arguments [Event ID 4688], PowerShell Script Block Logging [Event ID 4104], and detailed logon/logoff auditing), workstations typically generate between 100 MB and 300+ MB of security telemetry daily. A legacy 192 MB Security log preserves only 12 to 48 hours of telemetry, creating severe risks for endpoints operating off-network (remote users, field devices) where real-time Windows Event Forwarding (WEF) or SIEM shipping may be delayed.

Expanding the **Security** log to **1 GB** (`1,048,576 KB`), **System** and **Application** logs to **128 MB** (`131,072 KB`), and **Setup** log to **32 MB** (`32,768 KB`) provides a resilient 7-to-14-day on-box forensic retention buffer.

### Technical Engineering Considerations
1. **64 KB Boundary Alignment**: The Windows Event Log service allocates and writes event records in 64 KB memory blocks. All configured sizes in KB must be integer multiples of 64 (`SizeKB % 64 == 0`). Sizes that do not align with 64 KB boundaries are rounded down by the operating system (`1,048,576 / 64 = 16,384`; `131,072 / 64 = 2,048`; `32,768 / 64 = 512`).
2. **Retention Policy**: Configuring retention behavior to "Overwrite events as needed" (GPO: `Disabled`, registry value `0`) prevents the Event Log service from refusing new events or crashing when capacity is reached, guaranteeing continuous logging of recent attacker activity.
3. **Memory and I/O Impact**: Windows utilizes memory-mapped files (`.evtx`) for the Event Log service. Only actively accessed pages are mapped into virtual memory; larger file limits do not consume active physical RAM.
4. **Log Flooding & Anti-Forensics Defense**: Adversaries frequently flood event logs with benign telemetry to force rapid rollover and overwrite forensic traces of lateral movement, privilege escalation, or persistence. A 1 GB Security log buffer severely raises the bar for log flooding attacks, preserving critical evidence for digital forensics and incident response (DFIR).

---

## Legacy Impact & Compatibility

* **Operational Impact**: Allocates approximately 1.32 GB of maximum disk space in `%SystemRoot%\System32\Winevt\Logs`. Modern enterprise workstations with 256 GB to 1 TB SSDs easily absorb this footprint (representing less than 0.3% of total storage).
* **System Performance**: Memory-mapped architecture ensures zero perceptible impact on system responsiveness or CPU overhead during logging events.
* **WEF & SIEM Integration**: Provides robust offline buffering when roaming laptops or remote endpoints disconnect from enterprise VPNs or local collectors.
* **Rollout Recommendations**: High priority; deploy immediately across all Tier 2 workstations and member servers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`131072` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`1048576` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`32768` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System`
  * **Specify the maximum log file size (KB)**: Set to `Enabled` (`131072` KB)
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit (OU) and verify replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtEventLogSizes.ps1](../implementation_scripts/Configure-EndAtEventLogSizes.ps1)

```powershell
#Configure-EndAtEventLogSizes.ps1
# Description: Configures Administrative Templates: Event Log Maximum File Sizes and Retention Policies.

Write-Host "Configuring Administrative Templates: Event Log Maximum File Sizes and Retention Policies..." -ForegroundColor Cyan

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

Write-Host "[+] Administrative Templates: Event Log Maximum File Sizes and Retention Policies applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtEventLogSizesStatus.ps1](../audit_scripts/Get-EndAtEventLogSizesStatus.ps1)

```powershell
#Get-EndAtEventLogSizesStatus.ps1
# Description: Audits Administrative Templates: Event Log Maximum File Sizes and Retention Policies.

Write-Host "--- Auditing Administrative Templates: Event Log Maximum File Sizes and Retention Policies ---" -ForegroundColor Cyan
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

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

### Option C: Manual Verification

Verify the applied log configurations via command line using `wevtutil`:
```cmd
wevtutil gl Application
wevtutil gl Security
wevtutil gl Setup
wevtutil gl System
```
Verify that `maxSize` reflects the configured byte values (`1073741824` bytes for Security, `134217728` bytes for System/Application, `33554432` bytes for Setup) and `retention` is set to `false`.

---

## Sources & Compliance References
* **DoD Windows 10/11 Security Technical Implementation Guide (STIG)**: Rule SV-220707r879607_rule (Security Log MaxSize >= 1,024,000 KB), SV-220705r556754_rule (Application Log MaxSize >= 32,768 KB), SV-220709r556766_rule (System Log MaxSize >= 32,768 KB)
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.26.1.1, 18.10.26.1.2 (Application >= 32,768 KB), 18.10.26.2.1, 18.10.26.2.2 (Security >= 196,608 KB), 18.10.26.3.1, 18.10.26.3.2 (Setup >= 32,768 KB), 18.10.26.4.1, 18.10.26.4.2 (System >= 32,768 KB)
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions for Windows client platforms
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters and forensic preservation recommendations for managed Windows environments
* **MITRE ATT&CK**: [T1070.001: Indicator Removal on Host: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/), [T1562.002: Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)
* **Related Controls**: [REQ-DC-121: Domain Controller Event Log Maximum File Sizes and Retention Policies](../../02-domain-controllers/configure-event-log-sizes.md), [REQ-END-182: Administrative Templates: MSS System and Session Security Protections](configure-end-at-mss-system-protections.md)
