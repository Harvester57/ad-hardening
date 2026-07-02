# [REQ-PAW-032] Disable Unused Windows Features and PowerShell 2.0 Engine

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 hosts).
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path (PowerShell 2.0 Compatibility)**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell`
  * **Registry Location (PowerShell 2.0 Compatibility)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\PowerShellV2`
  * **Feature Disablement**: Deployed via Group Policy Startup Script or PowerShell Desired State Configuration (DSC) using DISM.

---

## Rationale
To enforce strict isolation and minimize the attack surface of Tier 0 Privileged Access Workstations, all unnecessary legacy protocols, optional features, and runtime engines must be disabled. 

1. **PowerShell 2.0 Engine**: Legacy PowerShell 2.0 does not support modern logging, transcription, or security monitoring mechanisms such as the Antimalware Scan Interface (AMSI). Attackers leverage "downgrade attacks" by executing PowerShell scripts using the `-version 2.0` parameter to bypass script block logging and security tooling. Disabling the engine and its parent runtimes eliminates this bypass vector.
2. **.NET Framework 3.5**: The .NET 3.5 Framework includes the runtime files for .NET 2.0 and 3.0. PowerShell 2.0 requires .NET 2.0/3.5 to run. Disabling `.NET Framework 3.5` removes legacy runtime binaries that are susceptible to downgrade attacks and removes support for older, unpatched software.
3. **SMBv1 Protocol**: The legacy SMBv1 protocol is cryptographically weak, lacks authentication integrity protection, and has been the target of catastrophic remote code execution attacks (such as EternalBlue). Leaving the SMBv1 driver active allows relaying and man-in-the-middle attacks.
4. **Internet Explorer 11**: Internet Explorer contains obsolete MSHTML render engine components. Disabling this legacy browser reduces vulnerability to web-based code execution.
5. **Work Folders, XPS, DirectPlay, and Client Protocols**: Services and tools such as Work Folders, XPS Viewer, DirectPlay, Telnet Client, TFTP Client, and Simple TCP/IP Services contain legacy network parsers and protocols that are completely unnecessary for a secure administrative system.
6. **WSL and Windows Sandbox**: Virtualization layers such as the Windows Subsystem for Linux (WSL) and Windows Sandbox allow the execution of unmonitored binaries, containers, and Linux utilities. On a PAW, these components present an unacceptable audit-bypass risk and must be disabled.

---

## Legacy Impact & Compatibility
* **Script Dependencies**: Any administrative scripts that depend on .NET Framework 2.0/3.0/3.5 will fail. All internal scripts must be updated to run on .NET 4.8 or modern .NET (Core) runtimes.
* **Legacy Management Software**: Old configuration managers or printers that require SMBv1 client capabilities to mount file shares will fail to connect.
* **Developer Tools**: Disabling WSL and Windows Sandbox on PAWs prevents the use of localized Docker configurations or container tests on the administrative device. PAWs must remain dedicated to administration, and developer workloads must be redirected to standard development endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Disable PowerShell 2.0 Compatibility Policy
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the target PAWs GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell`
4. Configure the following setting:
   * **Policy**: `Turn on PowerShell 2.0 Compatibility Mode`
   * **Setting**: `Disabled`
5. Link the GPO to the PAWs Organizational Unit (OU).

#### Step 2: Deploy Feature Disablement Startup Script
Because Windows Optional Features are managed via DISM/Packages and lack direct GPO settings for feature removal, deploy the disablement script as a Computer Startup script:
1. In the same GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Scripts (Startup/Shutdown)`
2. Double-click **Startup**, click the **PowerShell Scripts** tab.
3. Add the `Disable-PawUnusedFeatures.ps1` script to execute on system startup.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally or run it as a startup script.

[Download Script: Disable-PawUnusedFeatures.ps1](implementation_scripts/Disable-PawUnusedFeatures.ps1)

```powershell
# Disable-PawUnusedFeatures.ps1
# Description: Disables unused legacy features, .NET 3.5, and PowerShell 2.0 on the local PAW system.

Write-Host "Disabling unused legacy features and PowerShell 2.0..." -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

# Features to disable (Client OS DISM feature names)
$Features = @(
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root",
    "NetFx3",                                # .NET Framework 3.5
    "SMB1Protocol",                          # SMBv1 Client
    "Internet-Explorer-Optional-amd64",      # Internet Explorer 11
    "WorkFolders-Client",                    # Work Folders Client
    "Xps-Viewer-Dependency",                 # XPS Viewer
    "DirectPlay",                            # DirectPlay
    "TelnetClient",                          # Telnet Client
    "TFTP",                                  # TFTP Client
    "SimpleTCP",                             # Simple TCP/IP Services
    "Microsoft-Windows-Subsystem-Linux",     # WSL (specifically disabled on PAWs)
    "Containers-DisposableClientVM"          # Windows Sandbox (specifically disabled on PAWs)
)

foreach ($Feature in $Features) {
    $State = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction SilentlyContinue
    if ($null -ne $State) {
        if ($State.State -eq "Enabled" -or $State.State -eq "EnabledPendingRestart") {
            Write-Host "[*] Disabling feature: $Feature..." -ForegroundColor Yellow
            Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Feature '$Feature' has been disabled." -ForegroundColor Green
        } else {
            Write-Host "[~] Feature '$Feature' is already disabled." -ForegroundColor Gray
        }
    } else {
        Write-Host "[~] Feature '$Feature' is not present in this Windows image." -ForegroundColor Gray
    }
}

Write-Host "Optional features configuration completed." -ForegroundColor Green
```

*To verify the state of unused features:*

[Download Script: Get-PawUnusedFeaturesStatus.ps1](audit_scripts/Get-PawUnusedFeaturesStatus.ps1)

```powershell
# Get-PawUnusedFeaturesStatus.ps1
# Description: Audits the installation state of unused legacy features on the local PAW system.

Write-Host "--- Auditing Unused Windows Features ---" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

$script:Vulnerable = $false

# Features to check (Client OS DISM feature names)
$Features = @(
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root",
    "NetFx3",                                # .NET Framework 3.5
    "SMB1Protocol",                          # SMBv1 Client
    "Internet-Explorer-Optional-amd64",      # Internet Explorer 11
    "WorkFolders-Client",                    # Work Folders Client
    "Xps-Viewer-Dependency",                 # XPS Viewer
    "DirectPlay",                            # DirectPlay
    "TelnetClient",                          # Telnet Client
    "TFTP",                                  # TFTP Client
    "SimpleTCP",                             # Simple TCP/IP Services
    "Microsoft-Windows-Subsystem-Linux",     # WSL (specifically disabled on PAWs)
    "Containers-DisposableClientVM"          # Windows Sandbox (specifically disabled on PAWs)
)

foreach ($Feature in $Features) {
    $State = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction SilentlyContinue
    if ($null -ne $State) {
        $IsEnabled = ($State.State -eq "Enabled" -or $State.State -eq "EnabledPendingRestart")
        $Color = if (-not $IsEnabled) { "Green" } else { "Red" }
        Write-Host "    - Feature: $Feature | State: $($State.State) (Expected: Disabled)" -ForegroundColor $Color
        
        if ($IsEnabled) {
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - Feature: $Feature | Not Present (Compliant)" -ForegroundColor Green
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
* **DoD Windows 11 Computer STIG v2r6**: V-220728 (PowerShell 2.0), V-253286 (SMBv1), V-219524 (.NET Framework 3.5)
* **ANSSI AD Hardening Guide**: Section on Endpoint Minimization and disabling legacy protocols
* **CIS Microsoft Windows Client Benchmark**: Section 18.9 (PowerShell restrictions)
