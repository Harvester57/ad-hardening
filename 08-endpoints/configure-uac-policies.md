# Hardening Requirement: Configure User Account Control Policies

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
  * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

---

## Rationale
User Account Control (UAC) is a fundamental defense mechanism in Windows. It limits the privilege levels of running applications, executing administrative actions with standard user tokens unless elevated privileges are explicitly approved.

Hardening UAC settings ensures:
1. **Secure Desktop Enforcement**: The elevation prompt is displayed on a separate, secure desktop environment that isolated system threads run on. This prevents third-party malware running in user space from intercepting credentials or programmatically clicking "Yes" to elevate itself.
2. **Auto-Denial of Standard User Elevation**: Standard users should not be allowed to request elevation. If a standard user triggers a task requiring administrative rights, the prompt should auto-deny rather than requesting an administrator password, preventing users from attempting to bypass controls or exposing local admin passwords on a non-secure user terminal.
3. **Admin Approval Mode**: Forcing built-in administrators to run in Admin Approval Mode ensures that even administrative users do not run web browsers or document editors with administrative tokens by default.

---

## Legacy Impact & Compatibility
* **User Experience**: Standard users will not be able to install software or change system settings that require administrative credentials. Support technicians must log on as local administrators to perform maintenance tasks or use remote tools.
* **Script and Installer Behaviors**: Legacy scripts and administrative install tasks that run programmatically without secure-desktop awareness may fail or hang if they trigger elevation prompts that cannot be programmatically bypassed.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following settings:
   * **Policy**: `User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode`
   * **Setting**: `Prompt for credentials on the secure desktop`
   * **Policy**: `User Account Control: Behavior of the elevation prompt for standard users`
   * **Setting**: `Automatically deny elevation requests`
   * **Policy**: `User Account Control: Run all administrators in Admin Approval Mode`
   * **Setting**: `Enabled`
   * **Policy**: `User Account Control: Switch to the secure desktop when prompting for elevation`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure maximum security parameters for UAC in the system registry.

```powershell
# Configure-UACPolicies.ps1
# Enforces hardened User Account Control (UAC) registry configuration values.

Write-Host "--- Hardening User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}

# ConsentPromptBehaviorAdmin = 1 (Prompt for credentials on secure desktop)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord
# ConsentPromptBehaviorUser = 0 (Automatically deny elevation requests)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord
# EnableLUA = 1 (Enable User Account Control / Admin Approval Mode)
Set-ItemProperty -Path $SystemPath -Name "EnableLUA" -Value 1 -Type DWord
# PromptOnSecureDesktop = 1 (Switch to secure desktop when prompting)
Set-ItemProperty -Path $SystemPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord

Write-Host "[+] UAC registry values configured successfully." -ForegroundColor Green
```

*To audit UAC configurations:*
```powershell
# Test-UACPolicies.ps1
# Verifies local system registry settings for User Account Control.

Write-Host "--- Auditing User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$AdminPrompt = Get-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
$UserPrompt = Get-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
$LuaState = Get-ItemProperty -Path $SystemPath -Name "EnableLUA" -ErrorAction SilentlyContinue
$SecureDesk = Get-ItemProperty -Path $SystemPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue

$AdminVal = if ($AdminPrompt) { $AdminPrompt.ConsentPromptBehaviorAdmin } else { 0 }
$UserVal = if ($UserPrompt) { $UserPrompt.ConsentPromptBehaviorUser } else { 3 }
$LuaVal = if ($LuaState) { $LuaState.EnableLUA } else { 0 }
$SecureVal = if ($SecureDesk) { $SecureDesk.PromptOnSecureDesktop } else { 0 }

$AdminColor = if ($AdminVal -eq 1 -or $AdminVal -eq 3) { "Green" } else { "Red" }
$UserColor = if ($UserVal -eq 0) { "Green" } else { "Red" }
$LuaColor = if ($LuaVal -eq 1) { "Green" } else { "Red" }
$SecureColor = if ($SecureVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - ConsentPromptBehaviorAdmin: $AdminVal (Required = 1 [Prompt for Creds] or 3 [Prompt for Consent on Secure Desktop])" -ForegroundColor $AdminColor
Write-Host "    - ConsentPromptBehaviorUser: $UserVal (Required = 0 [Auto Deny])" -ForegroundColor $UserColor
Write-Host "    - EnableLUA: $LuaVal (Required = 1)" -ForegroundColor $LuaColor
Write-Host "    - PromptOnSecureDesktop: $SecureVal (Required = 1)" -ForegroundColor $SecureColor
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 2.3.17.1 (ConsentPromptBehaviorAdmin), Section 2.3.17.2 (ConsentPromptBehaviorUser), Section 2.3.17.5 (EnableLUA)
* **Microsoft Security Baselines**: Windows Client Security baseline registry settings.
