# [REQ-PAW-020] Configure User Account Control Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
    * `Computer Configuration\Administrative Templates\System`
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
      * `ConsentPromptBehaviorAdmin` = `1` (REG_DWORD, Prompt for credentials on secure desktop)
      * `ConsentPromptBehaviorUser` = `0` (REG_DWORD, Automatically deny elevation requests)
      * `EnableLUA` = `1` (REG_DWORD, Enable User Account Control / Admin Approval Mode)
      * `PromptOnSecureDesktop` = `1` (REG_DWORD, Switch to secure desktop when prompting)
      * `LocalAccountTokenFilterPolicy` = `0` (REG_DWORD, Apply UAC restrictions to local accounts on network logons)
      * `EnableInstallDetection` = `1` (REG_DWORD, Detect application installations and prompt for elevation)
      * `EnableVirtualization` = `1` (REG_DWORD, Virtualize file and registry write failures to per-user locations)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sudo`
      * `Enabled` = `1` (REG_DWORD, Sudo behavior set to force a new elevated window)

---

## Rationale
User Account Control (UAC) is a fundamental defense mechanism in Windows. It limits the privilege levels of running applications, executing administrative actions with standard user tokens unless elevated privileges are explicitly approved.

Hardening UAC settings ensures:
1. **Secure Desktop Enforcement**: The elevation prompt is displayed on a separate, secure desktop environment that isolated system threads run on. This prevents third-party malware running in user space from intercepting credentials or programmatically clicking "Yes" to elevate itself.
2. **Auto-Denial of Standard User Elevation**: Standard users should not be allowed to request elevation. If a standard user triggers a task requiring administrative rights, the prompt should auto-deny rather than requesting an administrator password, preventing users from attempting to bypass controls or exposing local admin passwords on a non-secure user terminal.
3. **Admin Approval Mode**: Forcing built-in administrators to run in Admin Approval Mode ensures that even administrative users do not run web browsers or document editors with administrative tokens by default.
4. **Sudo Command Control**: The `sudo` command introduced in Windows 11 (24H2) allows users to run elevated commands from an unelevated console. Leaving this feature unconfigured or allowing execution within the current console session can expose elevated processes to command injection or token interception in the same console session. Restricting `sudo` to opening a new elevated window (`1`) or disabling it entirely (`0`) mitigates session hijacking risks.
5. **Network UAC Restrictions (`LocalAccountTokenFilterPolicy`)**: Restricting the elevation of local accounts during network logons prevents lateral movement. When set to `0`, local accounts (except for the built-in Administrator RID 500 account) connecting remotely via network shares or administrative interfaces cannot obtain administrative tokens, neutralizing pass-the-hash attacks using secondary local administrative accounts.
6. **Installer Detection (`EnableInstallDetection`)**: Detecting installer program behavior prevents silent software execution. When enabled, any execution of an install file or setup program by standard users or administrators triggers a UAC elevation prompt, preventing unauthorized silent program deployments.
7. **UAC Virtualization (`EnableVirtualization`)**: Virtualizing writes redirection keeps the operating system directory space clean. It redirects legacy application registry and file writes targeting system folders (like `Program Files` or `System32`) to user-profile-specific folders, allowing legacy applications to run without requiring administrative rights.

---

## Legacy Impact & Compatibility
* **User Experience**: Standard users will not be able to install software or change system settings that require administrative credentials. Support technicians must log on as local administrators to perform maintenance tasks or use remote tools. Note that interactive logons for standard users are already blocked on PAWs via User Rights Assignments.
* **Script and Installer Behaviors**: Legacy scripts and administrative install tasks that run programmatically without secure-desktop awareness may fail or hang if they trigger elevation prompts that cannot be programmatically bypassed.
* **Network Admin Access**: Network-based remote administration using local accounts will be restricted to the RID 500 account. Domain accounts must be used for remote administrative access (WinRM, SMB administration) on standard endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following settings:
   * **Policy**: `User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode` -> **Prompt for credentials on the secure desktop**
   * **Policy**: `User Account Control: Behavior of the elevation prompt for standard users` -> **Automatically deny elevation requests**
   * **Policy**: `User Account Control: Run all administrators in Admin Approval Mode` -> **Enabled**
   * **Policy**: `User Account Control: Switch to the secure desktop when prompting for elevation` -> **Enabled**
   * **Policy**: `User Account Control: Detect application installations and prompt for elevation` -> **Enabled**
   * **Policy**: `User Account Control: Virtualize file and registry write failures to per-user locations` -> **Enabled**
5. Since the UAC network restrictions policy is not directly exposed in standard GPO security templates, deploy the registry setting via GPO Preferences:
   * Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
   * Create a new Registry Item:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
     * **Value Name**: `LocalAccountTokenFilterPolicy`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `0`
6. Navigate to: `Computer Configuration\Administrative Templates\System`
   * **Policy**: `Configure the behavior of the sudo command` -> **Enabled** with options set to **Force a new elevated window**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure maximum security parameters for UAC in the system registry.

[Download Script: Configure-PawUACPolicies.ps1](implementation_scripts/Configure-PawUACPolicies.ps1)

```powershell
# Configure-PawUACPolicies.ps1
# Description: Enforces hardened User Account Control (UAC) registry configuration values including network restrictions, installer detection, and virtualization on PAWs.

Write-Host "--- Hardening User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}

# ConsentPromptBehaviorAdmin = 1 (Prompt for credentials on secure desktop)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord -Force
# ConsentPromptBehaviorUser = 0 (Automatically deny elevation requests)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -Force
# EnableLUA = 1 (Enable User Account Control / Admin Approval Mode)
Set-ItemProperty -Path $SystemPath -Name "EnableLUA" -Value 1 -Type DWord -Force
# PromptOnSecureDesktop = 1 (Switch to secure desktop when prompting)
Set-ItemProperty -Path $SystemPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
# LocalAccountTokenFilterPolicy = 0 (Apply UAC restrictions to local accounts on network logons)
Set-ItemProperty -Path $SystemPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -Force
# EnableInstallDetection = 1 (Detect application installations and prompt for elevation)
Set-ItemProperty -Path $SystemPath -Name "EnableInstallDetection" -Value 1 -Type DWord -Force
# EnableVirtualization = 1 (Virtualize file and registry write failures to per-user locations)
Set-ItemProperty -Path $SystemPath -Name "EnableVirtualization" -Value 1 -Type DWord -Force

# Configure Windows Sudo command behavior (Enabled = 1 [Force new elevated window])
$SudoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo"
if (-not (Test-Path $SudoPath)) {
    New-Item -Path $SudoPath -Force | Out-Null
}
Set-ItemProperty -Path $SudoPath -Name "Enabled" -Value 1 -Type DWord -Force

Write-Host "[+] UAC registry values configured successfully." -ForegroundColor Green
```

*To audit UAC configurations on the PAW:*

[Download Script: Test-PawUACPolicies.ps1](audit_scripts/Test-PawUACPolicies.ps1)

```powershell
# Test-PawUACPolicies.ps1
# Description: Verifies local system registry settings for User Account Control on PAWs.

Write-Host "--- Auditing User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$script:Vulnerable = $false

function Test-UACRegistryValue ($name, $expected, $message) {
    $val = Get-ItemProperty -Path $SystemPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { $null }
    $color = "Red"
    if ($actual -eq $expected) {
        $color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $name | Actual: '$actual' (Expected: '$expected') | $message" -ForegroundColor $color
}

Test-UACRegistryValue "ConsentPromptBehaviorAdmin" 1 "Behavior of elevation prompt for administrators"
Test-UACRegistryValue "ConsentPromptBehaviorUser" 0 "Behavior of elevation prompt for standard users"
Test-UACRegistryValue "EnableLUA" 1 "Run all administrators in Admin Approval Mode"
Test-UACRegistryValue "PromptOnSecureDesktop" 1 "Switch to secure desktop when prompting"
Test-UACRegistryValue "LocalAccountTokenFilterPolicy" 0 "UAC network restrictions"
Test-UACRegistryValue "EnableInstallDetection" 1 "Installer detection"
Test-UACRegistryValue "EnableVirtualization" 1 "UAC virtualization"

# Audit Sudo command
$SudoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo"
if (Test-Path $SudoPath) {
    $SudoState = Get-ItemProperty -Path $SudoPath -Name "Enabled" -ErrorAction SilentlyContinue
    $SudoVal = if ($SudoState) { $SudoState.Enabled } else { 0 }
    $SudoColor = if ($SudoVal -eq 0 -or $SudoVal -eq 1) { "Green" } else { "Red" }
    Write-Host "    - Sudo Command Enabled state: $SudoVal (Required = 1 [New Window] or 0 [Disabled])" -ForegroundColor $SudoColor
    if ($SudoVal -ne 0 -and $SudoVal -ne 1) {
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - Sudo Command Enabled state: Not Configured (Default/Compliant as it inherits disabled)" -ForegroundColor Green
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
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 2.3.17.1 (ConsentPromptBehaviorAdmin), Section 2.3.17.2 (ConsentPromptBehaviorUser), Section 2.3.17.4 (EnableInstallDetection), Section 2.3.17.5 (EnableLUA), Section 2.3.17.8 (EnableVirtualization)
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 18.4.1 (LocalAccountTokenFilterPolicy)
* **Microsoft Security Baselines**: Windows Client Security baseline registry settings.
