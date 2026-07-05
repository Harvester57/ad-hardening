# [REQ-END-075] Configure Sandbox Execution Environment

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Preferences\Windows Settings\Environment`
  * **Registry Location**:
    * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
      * `MP_FORCE_USE_SANDBOX` = `1` (REG_SZ)

---

## Rationale
Forcing the Windows Defender scanning service (MsMpEng.exe) to run in a restricted AppContainer sandbox prevents privilege escalation. If an attacker exploits a parsing vulnerability in the engine, the compromise is contained inside the sandbox.

---

## Legacy Impact & Compatibility
A system reboot is required to initialize the scanning process within the AppContainer sandbox.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Preferences\Windows Settings\Environment
2. Right-click and select New -> Environment Variable
3. Configure Action: Update, Type: System, Name: MP_FORCE_USE_SANDBOX, Value: 1

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderSandbox.ps1](../implementation_scripts/Configure-DefenderSandbox.ps1)

```powershell
# Configure-DefenderSandbox.ps1
$EnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
if (-not (Test-Path $EnvPath)) { New-Item -Path $EnvPath -Force | Out-Null }
Set-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderSandboxStatus.ps1](../audit_scripts/Get-DefenderSandboxStatus.ps1)

```powershell
# Get-DefenderSandboxStatus.ps1
$EnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$SandboxVar = Get-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -ErrorAction SilentlyContinue
if ($SandboxVar -and $SandboxVar.MP_FORCE_USE_SANDBOX -eq "1") {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
