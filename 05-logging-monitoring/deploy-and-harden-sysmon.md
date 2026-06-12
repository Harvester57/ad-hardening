# Hardening Requirement: Deploy and Harden Microsoft Sysmon

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Service Configurations**: Local service parameters managed via startup script or scheduled task.
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\Sysmon` and `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv`

---

## Rationale
Windows Security event logs lack detailed telemetry on low-level operating system actions, such as process memory reads (e.g., LSASS dumping via Mimikatz), thread injection, network connections associated with process IDs, and driver loading. Microsoft Sysmon (System Monitor) bridges this gap by writing rich system monitoring telemetry to the `Microsoft-Windows-Sysmon/Operational` event log channel.

Because Sysmon is a critical detection source, adversaries actively target it by attempting to unload its filter driver (`sysmon -u` or `fltmc unload SysmonDrv`) or stopping/disabling the Sysmon service (`sc stop Sysmon`). 

Hardening Sysmon involves:
1. **Service Recovery Configuration**: Forcing the operating system to automatically restart the Sysmon service on failure or termination.
2. **Telemetry Filtering**: Deploying a hardened, security-focused XML configuration template that filters out noise while logging process creation (Event ID 1), remote threads (Event ID 8), LSASS memory access (Event ID 10), and suspicious file drops (Event ID 11).

---

## Legacy Impact & Compatibility
* **Driver Performance**: Sysmon loads a kernel-mode filter driver (`SysmonDrv`). This driver must be tested in staging environments on Domain Controllers and high-load servers to ensure compatibility and that it does not introduce performance bottlenecks.
* **Log Rotation**: Sysmon logs generate substantial volume. The `Microsoft-Windows-Sysmon/Operational` event log channel must be sized to at least 1GB on domain controllers and critical systems to prevent loss of telemetry due to wrap-around log overwriting.

---

## Implementation Steps

### Option A: Installation and Service Configuration

#### 1. Install Sysmon with Hardened XML Base Configuration
Deploy Sysmon using the command line with a local XML configuration file. Save the following template as `sysmon-config.xml` in a secure administrative path:

```xml
<Sysmon schemaversion="4.50">
  <HashAlgorithms>md5,sha256,imphash</HashAlgorithms>
  <EventFiltering>
    <!-- Rule Group: Process Creation (Event ID 1) -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
    </RuleGroup>
    
    <!-- Rule Group: Network Connections (Event ID 3) -->
    <RuleGroup name="Network Connection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">22</DestinationPort>
        <DestinationPort condition="is">3389</DestinationPort>
        <DestinationPort condition="is">445</DestinationPort>
        <DestinationPort condition="is">5985</DestinationPort>
        <DestinationPort condition="is">5986</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Rule Group: Driver Load (Event ID 6) -->
    <RuleGroup name="Driver Load" groupRelation="or">
      <DriverLoad onmatch="exclude" />
    </RuleGroup>

    <!-- Rule Group: CreateRemoteThread (Event ID 8) -->
    <RuleGroup name="CreateRemoteThread" groupRelation="or">
      <CreateRemoteThread onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <TargetImage condition="end with">spoolsv.exe</TargetImage>
      </CreateRemoteThread>
    </RuleGroup>

    <!-- Rule Group: Process Access (Event ID 10) -->
    <RuleGroup name="Process Access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Rule Group: File Creation (Event ID 11) -->
    <RuleGroup name="File Creation" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Startup\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Run the installer via administrative command line:
```cmd
Sysmon64.exe -i sysmon-config.xml -accepteula
```

#### 2. Enforce Service Recovery settings
Configure the Windows Service Control Manager to automatically restart the Sysmon service if it is terminated:
```cmd
sc.exe failure Sysmon actions= restart/60000/restart/60000/restart/60000 reset= 86400
```
*(Note: Ensure there is a space after the `=` sign for both parameters).*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to deploy/configure Sysmon and verify its operational state.

[Download Script: Set-SysmonHardening.ps1](implementation_scripts/Set-SysmonHardening.ps1)

```powershell
# Set-SysmonHardening.ps1
# Configures Sysmon service recovery settings.

Write-Host "--- Hardening Sysmon Service Recovery Settings ---" -ForegroundColor Cyan

# 1. Ensure Sysmon Service is installed and configured
$SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if (-not $SysmonService) {
    Write-Warning "Sysmon service is not currently installed. Run the Sysmon installer first."
    exit 1
}

# 2. Configure Service Failure Recovery options via sc.exe
Write-Host "[+] Configuring service failure recovery actions for Sysmon..." -ForegroundColor Gray
$ScArgs = "failure Sysmon actions= restart/60000/restart/60000/restart/60000 reset= 86400"
$Process = Start-Process sc.exe -ArgumentList $ScArgs -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Sysmon service recovery actions successfully set to auto-restart." -ForegroundColor Green
} else {
    Write-Error "    Failed to set service recovery settings. Exit Code: $($Process.ExitCode)"
}
```

*To verify the settings have been applied:*

[Download Script: Test-SysmonHardening.ps1](audit_scripts/Test-SysmonHardening.ps1)

```powershell
# Test-SysmonHardening.ps1
# Audits Sysmon service, driver execution, and recovery actions.

Write-Host "--- Auditing Sysmon Hardening State ---" -ForegroundColor Cyan

# 1. Verify Sysmon Service status
$SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
$ServiceStatus = "Stopped"
if ($SysmonService) {
    $ServiceStatus = $SysmonService.Status
}
$ServiceColor = if ($ServiceStatus -eq "Running") { "Green" } else { "Red" }
Write-Host "    - Sysmon Service Status: $($ServiceStatus) (Required = Running)" -ForegroundColor $ServiceColor

# 2. Verify Sysmon Filter Driver (SysmonDrv)
$DriverRunning = $false
$DriverCheck = fltmc.exe filters
foreach ($Line in $DriverCheck) {
    if ($Line -match "SysmonDrv") {
        $DriverRunning = $true
    }
}
$DriverColor = if ($DriverRunning) { "Green" } else { "Red" }
Write-Host "    - Sysmon Kernel Driver Loaded: $($DriverRunning) (Required = True)" -ForegroundColor $DriverColor

# 3. Verify Service Failure Recovery Options
$FailureInfo = sc.exe qfailure Sysmon
$HasReset = $false
$HasRestart = $false
foreach ($Line in $FailureInfo) {
    if ($Line -match "RESET_PERIOD\s+:\s+86400") {
        $HasReset = $true
    }
    if ($Line -match "FAILURE_ACTIONS\s+:\s+RESTART") {
        $HasRestart = $true
    }
}

$RecoveryColor = if ($HasReset -and $HasRestart) { "Green" } else { "Red" }
Write-Host "    - Recovery Configuration: ResetConfigured=$($HasReset), RestartActionsConfigured=$($HasRestart)" -ForegroundColor $RecoveryColor
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R52 (Use of Sysmon and host log analysis)
* **CIS Benchmark**: Recommended baseline practice for advanced security monitoring
* **Microsoft Security Guidance**: Sysmon configuration best practices
