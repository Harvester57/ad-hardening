# Module 5: Logging, Monitoring & SIEM

This module outlines requirements for configuring advanced event logging and forwarding systems to detect security anomalies. In isolated, air-gapped environments, local logs are the primary telemetry source for incident response and threat detection.

---

## 1. Advanced Security Audit Policy

Standard Windows event logging is insufficient. Administrators must configure **Advanced Security Audit Policies** via GPO to log detailed events without overwhelming log storage.

### Key Audit Policies & Settings

| Subcategory | Policy Setting | Event IDs to Monitor | Purpose |
| :--- | :--- | :--- | :--- |
| **Audit Kerberos Authentication Service** | Success & Failure | 4768 | Kerberos TGT requests (detects brute force) |
| **Audit Kerberos Service Ticket Operations**| Success & Failure | 4769, 4770 | TGS requests (detects Kerberoasting/Silver Ticket) |
| **Audit Credential Validation** | Success & Failure | 4776 | NTLM validation (detects NTLM authentication) |
| **Audit User Account Management** | Success & Failure | 4720, 4722, 4724 | Account creation, enablement, password resets |
| **Audit Security Group Management** | Success & Failure | 4728, 4732, 4756 | Additions to privileged groups (Domain Admins, etc.) |
| **Audit Process Creation** | Success & Failure | 4688 | Tracks executables run on system |
| **Audit Directory Service Changes** | Success & Failure | 5136 | AD object modifications (ANSSI R48) |
| **Audit Directory Service Access** | Success & Failure | 4662 | AD object queries (detects AD enumeration tools) |

---

## 2. Command Line and PowerShell Auditing

Attackers rely on living-off-the-land binaries (Lolbins) and PowerShell scripts to run malware and extract passwords in-memory.

### Command Line Auditing
* **Requirement**: Enable "Include command line in process creation events" via Group Policy. This injects the exact arguments used into Security Event ID 4688.

### PowerShell Logging (ANSSI R50)
* **Script Block Logging**: Enforce Script Block Logging (Event ID 4104). This captures full blocks of code executed by PowerShell, even if obfuscated or generated dynamically in memory.
* **Module Logging**: Enforce Module Logging (Event ID 4103) to track pipeline execution details.
* **PowerShell Transcription**: Enable transcripts, sending outputs to a dedicated, read-only local directory for forensic auditing.

---

## 3. Sysmon (System Monitor) Hardening

Windows Event Log lacks detailed file system, network socket, and memory access telemetry. **Microsoft Sysmon** fills this gap locally.

* **Requirement**: Install Sysmon on all Domain Controllers and critical workstations.
* **Configuration**: Use a hardened, security-focused configuration file (e.g., modular configurations based on SwiftOnSecurity guidelines) to capture:
  * **Event ID 1**: Process creation (with command line and parent process).
  * **Event ID 3**: Network connections initiated by processes.
  * **Event ID 8**: CreateRemoteThread (detects injection into LSASS or other processes).
  * **Event ID 10**: ProcessAccess (detects memory reading of LSASS, e.g., Mimikatz).
  * **Event ID 11**: File creation events (detects dropping scripts).

---

## 4. Offline SIEM Shipping (Winlogbeat / Wazuh)

In isolated environments, logs must be shipped from local Event Logs to an offline centralized SIEM (such as a local ELK Stack or Wazuh Manager).

### Winlogbeat Configuration
Winlogbeat runs as a service on Windows machines to forward event logs.
* **Service Config (`winlogbeat.yml`)**:
  Configure it to ship the `Security`, `System`, `Microsoft-Windows-Sysmon/Operational`, and `Microsoft-Windows-PowerShell/Operational` channels.
  ```yaml
  winlogbeat.event_logs:
    - name: Security
    - name: System
    - name: Microsoft-Windows-Sysmon/Operational
    - name: Microsoft-Windows-PowerShell/Operational
  output.logstash:
    hosts: ["local-logstash.internal.local:5044"]
  ```

### Wazuh Agent Configuration
Wazuh agents can monitor Event Logs directly.
* **Service Config (`ossec.conf`)**:
  Include local files to monitor:
  ```xml
  <localfile>
    <location>Security</location>
    <log_format>eventlog</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventlog</log_format>
  </localfile>
  ```

---

## PowerShell Implementation Guide

### 1. Auditing Logging and Audit Policy Settings (Audit)

Run this script to audit if command-line auditing, PowerShell logging, and Advanced Audit Policies are active.

```powershell
# Audit-ADLogging.ps1
# Audits the current state of local logging configurations.

Write-Host "--- Auditing Logging & Monitoring Settings ---" -ForegroundColor Cyan

# 1. Audit PowerShell Script Block Logging
$psPolicyReg = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sbLoggingVal = 0
if (Test-Path $psPolicyReg) {
    $sbProp = Get-ItemProperty -Path $psPolicyReg -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($sbProp) { $sbLoggingVal = $sbProp.EnableScriptBlockLogging }
}
$sbColor = if ($sbLoggingVal -eq 1) { "Green" } else { "Red" }
Write-Host "[*] PowerShell Script Block Logging: $(if ($sbLoggingVal -eq 1) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $sbColor

# 2. Audit Command Line Process Auditing
$procAuditReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$cmdLineAuditVal = 0
if (Test-Path $procAuditReg) {
    $cmdProp = Get-ItemProperty -Path $procAuditReg -Name "ProcessCreationIncludeCmdLine_Policy" -ErrorAction SilentlyContinue
    if ($cmdProp) { $cmdLineAuditVal = $cmdProp.ProcessCreationIncludeCmdLine_Policy }
}
$cmdColor = if ($cmdLineAuditVal -eq 1) { "Green" } else { "Red" }
Write-Host "[*] Process Command Line Auditing: $(if ($cmdLineAuditVal -eq 1) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $cmdColor

# 3. Audit Specific Advanced Audit Policy Subcategories using auditpol.exe
Write-Host "[+] Querying Advanced Security Audit Policies..." -ForegroundColor Yellow
$categories = @(
    "Process Creation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "Directory Service Changes",
    "Security Group Management"
)

foreach ($cat in $categories) {
    $rawOutput = auditpol.exe /get /subcategory:$cat /r
    # Parse CSV format from auditpol: Machine,Subcategory,GUID,PolicyVal
    if ($rawOutput -match "^.+,$cat,.+,(.+)$") {
        $policyVal = $Matches[1]
        $color = if ($policyVal -match "Success and Failure" -or $policyVal -match "Success") { "Green" } else { "Red" }
        Write-Host "    - Subcategory: $cat | Setting: $policyVal" -ForegroundColor $color
    } else {
        Write-Warning "    - Subcategory: $cat | Status: Could not parse status."
    }
}
```

### 2. Enforcing Logging and Auditing Policies (Remediation)

Execute the following PowerShell script to enforce local registry keys for PowerShell Script Block Logging, Command Line Auditing, and run `auditpol.exe` to configure Advanced Security Auditing.

```powershell
# Set-ADLoggingRemediation.ps1
# Configures local audit settings, PowerShell logging, and command-line auditing.

Write-Host "--- Applying Logging & Monitoring Remediation ---" -ForegroundColor Cyan

# 1. Enable PowerShell Script Block Logging (EnableScriptBlockLogging = 1)
Write-Host "[+] Enforcing PowerShell Script Block Logging..." -ForegroundColor Gray
$psPolicyReg = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psPolicyReg)) {
    New-Item -Path $psPolicyReg -Force | Out-Null
}
Set-ItemProperty -Path $psPolicyReg -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-Host "    PowerShell Script Block Logging enabled." -ForegroundColor Green

# 2. Enable Command Line Auditing (ProcessCreationIncludeCmdLine_Policy = 1)
Write-Host "[+] Enforcing Process Creation Command Line Auditing..." -ForegroundColor Gray
$procAuditReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $procAuditReg)) {
    New-Item -Path $procAuditReg -Force | Out-Null
}
Set-ItemProperty -Path $procAuditReg -Name "ProcessCreationIncludeCmdLine_Policy" -Value 1 -Type DWord
Write-Host "    Process command line auditing enabled." -ForegroundColor Green

# 3. Configure Advanced Security Audit Policies via auditpol.exe
Write-Host "[+] Enforcing Advanced Security Audit Policies..." -ForegroundColor Gray

# Define policy configurations to apply: /success:enable /failure:enable
$policies = @(
    @{ Subcategory = "Process Creation"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Directory Service Changes"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Directory Service Access"; Success = "enable"; Failure = "enable" }
)

foreach ($p in $policies) {
    $sub = $p.Subcategory
    $succ = $p.Success
    $fail = $p.Failure
    
    # Run auditpol
    $args = "/set /subcategory:`"$sub`" /success:$succ /failure:$fail"
    $process = Start-Process auditpol -ArgumentList $args -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "    Audit policy '$sub' set to Success:$succ / Failure:$fail." -ForegroundColor Green
    } else {
        Write-Error "    Failed to set audit policy for '$sub'. Exit Code: $($process.ExitCode)"
    }
}

Write-Host "`nLogging and Auditing remediation applied successfully." -ForegroundColor Cyan
```
