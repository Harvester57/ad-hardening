# Hardening Requirement: Configure AppLocker Policies on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Service Configuration (GPO)**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Application Identity` -> Automatic
  * **AppLocker Path (GPO)**: `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
  * **Registry Location (Service)**: `HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc` -> `Start` = `2` (REG_DWORD)
  * **Registry Location (Enforcement)**: `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

---

## Rationale
Domain Controllers are Tier 0 administrative assets and must never be used for general-purpose tasks like web browsing, document viewing, or running unapproved utilities. Attackers who compromise a Domain Controller or obtain administrative access often attempt to execute custom binaries, remote access tools (RATs), or script-based tools to pivot, establish persistence, or extract the Active Directory database (NTDS.dit).

Enforcing AppLocker policies on Domain Controllers provides the following defense-in-depth security benefits:
1. **Restricts Execution to Authorized Software**: Prevents execution of unapproved software, preventing standard user directories (such as `C:\Users\` or `C:\Windows\Temp\`) from being used to launch malicious binaries or scripts.
2. **Blocks Browser Execution**: Prevents administrative users from launching web browsers (Chrome, Edge, Firefox, Internet Explorer) directly on Domain Controllers, shutting down web-based drive-by downloads and browser-based credential leakage.
3. **Restricts Windows Installer and Script Execution**: Prevents unauthorized `.msi` installations and unauthorized PowerShell or VBScript scripts from running, reducing the likelihood of successful exploitation via living-off-the-land techniques.

---

## Legacy Impact & Compatibility
* **Third-Party Administrative Tools**: Monitoring agents, backup orchestrators, and system management tools that run from custom directories (outside `%ProgramFiles%` or `%WinDir%`) will be blocked unless explicit path, publisher, or hash rules are created to whitelist them.
* **Audit Mode Verification**: It is highly recommended to deploy AppLocker in **Audit Only** mode for a baseline period (e.g., 30 days) to identify all legitimate software and administrative scripts. Analyze the event log (`Applications and Services Logs\Microsoft\Windows\AppLocker`) to create the necessary whitelist rules before switching to **Enforce rules** mode.
* **AppIDSvc Service**: AppLocker relies on the **Application Identity** service (`AppIDSvc`) to evaluate rule enforcement. If the service is not running, rules will not be enforced.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Enable Application Identity Service
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting Domain Controllers (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Double-click **Application Identity**.
5. Select **Define this policy setting** and configure the startup mode to **Automatic**.

#### 2. Configure AppLocker Enforcement
1. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
2. Right-click **AppLocker** and select **Properties**.
3. Under the **Enforcement** tab, check **Configured** for the following rule collections:
   * **Executable rules** -> Select **Enforce rules** (or **Audit only** for baseline testing)
   * **Windows Installer rules** -> Select **Enforce rules** (or **Audit only**)
   * **Script rules** -> Select **Enforce rules** (or **Audit only**)
   * **Packaged app rules** -> Select **Enforce rules** (or **Audit only**)
4. Click **OK**.

#### 3. Create Default and Block Rules
1. Expand **AppLocker** and select **Executable Rules**.
2. Right-click **Executable Rules** and select **Create Default Rules** (allows all files in Windows and Program Files directories, and allows local Administrators to run all files).
3. To block web browsers on Domain Controllers, create a deny rule:
   * Right-click **Executable Rules** and select **Create New Rule...**
   * Action: **Deny** | User or Group: **Everyone**
   * Publisher Rule: Browse and select the executable for Microsoft Edge (`msedge.exe`), Google Chrome (`chrome.exe`), Mozilla Firefox (`firefox.exe`), and Internet Explorer (`iexplore.exe`). Set rule to block all versions.
4. Repeat the default rule creation process for **Windows Installer Rules**, **Script Rules**, and **Packaged App Rules**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure the Application Identity service and verify AppLocker configuration. Note that local AppLocker policies are typically managed by importing XML configurations.

```powershell
# Set-AppLockerDCPolicy.ps1
# Description: Configures the Application Identity service and imports a basic local AppLocker XML policy.

Write-Host "Applying hardening requirement: Configure AppLocker on Domain Controllers..." -ForegroundColor Cyan

# 1. Enable Application Identity service (AppIDSvc)
$Service = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($Service) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    if ($Service.Status -ne "Running") {
        Start-Service -Name AppIDSvc
    }
    Write-Host "[+] Application Identity service configured to start automatically and is running." -ForegroundColor Green
} else {
    Write-Error "Application Identity service (AppIDSvc) is not present on this system."
}

# 2. Configure local AppLocker policy (Example: Enforces Executable, Installer, Script and Packaged App rules)
# Typically, an AppLocker XML configuration is imported. Below is the registry path configuration for baseline.
$SrpPath = "HKLM:\Software\Policies\Microsoft\Windows\SrpV2"
if (-not (Test-Path $SrpPath)) {
    New-Item -Path $SrpPath -Force | Out-Null
}

$Collections = @("Exe", "Msi", "Script", "Appx")
foreach ($Col in $Collections) {
    $ColPath = "$SrpPath\$Col"
    if (-not (Test-Path $ColPath)) {
        New-Item -Path $ColPath -Force | Out-Null
    }
    # EnforcementMode: 1 = Enforce, 0 = Audit Only
    Set-ItemProperty -Path $ColPath -Name "EnforcementMode" -Value 1 -Type DWord
}
Write-Host "[+] AppLocker enforcement registry values configured." -ForegroundColor Green
```

*To audit the Application Identity service and AppLocker registry configuration:*
```powershell
# Get-AppLockerDCStatus.ps1
# Description: Checks the configuration state of the AppIDSvc service and AppLocker registry paths.

Write-Host "--- Auditing AppLocker Configuration ---" -ForegroundColor Cyan

# 1. Audit service state
$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppIDSvc) {
    $SvcColor = if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") { "Green" } else { "Yellow" }
    Write-Host "    - Application Identity Service: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType) (Expected: Running | Automatic)" -ForegroundColor $SvcColor
} else {
    Write-Host "    - Application Identity Service: NOT INSTALLED" -ForegroundColor Red
}

# 2. Audit enforcement registry settings
$SrpPath = "HKLM:\Software\Policies\Microsoft\Windows\SrpV2"
$Collections = @("Exe", "Msi", "Script", "Appx")

if (Test-Path $SrpPath) {
    foreach ($Col in $Collections) {
        $ColPath = "$SrpPath\$Col"
        if (Test-Path $ColPath) {
            $Val = Get-ItemProperty -Path $ColPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
            if ($null -ne $Val) {
                $Mode = if ($Val.EnforcementMode -eq 1) { "Enforced" } else { "Audit Only" }
                $Color = if ($Val.EnforcementMode -eq 1) { "Green" } else { "Yellow" }
                Write-Host "    - Collection $Col Enforcement: $Mode (Value: $($Val.EnforcementMode))" -ForegroundColor $Color
            } else {
                Write-Host "    - Collection $Col Enforcement: NOT CONFIGURED" -ForegroundColor Red
            }
        } else {
            Write-Host "    - Collection $Col Path: NOT FOUND" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[-] AppLocker registry base path (SrpV2) not found. Policy is not deployed." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 3.1.2 (System hardening and configuration baseline controls)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9 (Application Control Policies / AppLocker)
* **Microsoft Security Baseline Focus**: Domain Controller Security baseline - AppLocker configurations
