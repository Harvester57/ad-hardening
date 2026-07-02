# [REQ-END-033] Configure Microsoft Office Security and Block OLE Packages

## Target Scope
* **Applicable Systems**: Member Workstations (Endpoints)
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings
  * **Registry Locations**:
    * `HKCU\software\policies\microsoft\office\16.0\common\security`
      * `vbawarnings` = `3` (REG_DWORD, Enforce macro signing / Block unsigned macros)
    * `HKCU\software\policies\microsoft\office\16.0\excel\security`
      * `blockcontentexecutionfrominternet` = `1` (REG_DWORD, Block macros in files from the Internet)
    * `HKCU\software\policies\microsoft\office\16.0\word\security`
      * `blockcontentexecutionfrominternet` = `1` (REG_DWORD)
    * `HKCU\software\policies\microsoft\office\16.0\powerpoint\security`
      * `blockcontentexecutionfrominternet` = `1` (REG_DWORD)
    * `HKCU\software\policies\microsoft\office\16.0\outlook\security`
      * `ShowOLEPackageObj` = `0` (REG_DWORD, Disable OLE package activation)

---

## Rationale
Malicious documents (e.g., weaponized Word, Excel, or PowerPoint files) containing embedded VBA macros are a prevalent initial access and execution vector. Similarly, embedding malicious OLE packages inside Outlook items (such as RTF-formatted emails) allows attackers to trigger script execution or execute arbitrary packages via `packager.dll` when an administrator or standard user opens or previews the email.

Hardening these settings ensures:
1. **Internet Macro Blocking**: VBA macros in files downloaded from the Internet or untrusted external attachments are blocked from executing, regardless of user consent.
2. **Macro Code Signing**: Any locally run macros are restricted to trusted, digitally signed code, preventing the execution of ad-hoc unverified user scripts.
3. **OLE Package Disablement**: Restricting Outlook OLE package activation (`ShowOLEPackageObj = 0`) blocks the execution of dangerous embedded objects in email messages.

---

## Legacy Impact & Compatibility
* **Office Macros**: Business workflows relying on macro-enabled spreadsheets or documents downloaded from external sources (e.g., vendor portals) will be blocked. Unsigned local macros will also fail to run. Users must acquire certificates to digitally sign internal macro projects.
* **Outlook Packages**: Embedded document shortcuts or packages in emails will be displayed as static icons and cannot be double-clicked for direct execution.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Enforce Macro Security in ADMX Templates
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO.
3. Navigate to: `User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings\Trust Center`
4. Set the following policies:
   * **Policy**: `VBA Macro Notification Settings` -> **Enabled** with option set to **Disable all except digitally signed macros**
5. For each application (Word, Excel, PowerPoint, Access), navigate to:
   `User Configuration\Policies\Administrative Templates\[Application] 2016\[Application] Options\Security\Trust Center`
6. Set the policy:
   * **Policy**: `Block macros from running in Office files from the Internet` -> **Enabled**

#### Step 2: Disable Outlook OLE Packages
1. Navigate to: `User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security`
2. Configure the setting:
   * **Policy**: `Do not allow OLE package execution` -> **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the current user registry hives to enforce macro blocking and OLE package restrictions.

[Download Script: Configure-OfficeSecurity.ps1](implementation_scripts/Configure-OfficeSecurity.ps1)

```powershell
# Configure-OfficeSecurity.ps1
# Description: Configures registry settings under the HKCU hive to restrict VBA macros and block Outlook OLE package execution.

Write-Host "Applying Microsoft Office security and OLE restrictions..." -ForegroundColor Cyan

# Helper to configure User Registry DWORD values
function Set-UserRegDWord {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    if ($PSCmdlet.ShouldProcess($Path, "Set registry DWORD value $Name to $Value")) {
        $FullRegistryPath = "HKCU:\$Path"
        if (-not (Test-Path $FullRegistryPath)) {
            New-Item -Path $FullRegistryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $FullRegistryPath -Name $Name -Value $Value -Type DWord -Force
    }
}

# 1. Enforce macro signing policy (common)
Set-UserRegDWord "software\policies\microsoft\office\16.0\common\security" "vbawarnings" 3
Write-Host "[+] Digital signing for Office macros enforced." -ForegroundColor Green

# 2. Block macros from the Internet for key Office applications
$Apps = @("excel", "word", "powerpoint", "access", "visio")
foreach ($App in $Apps) {
    Set-UserRegDWord "software\policies\microsoft\office\16.0\$App\security" "blockcontentexecutionfrominternet" 1
}
Write-Host "[+] VBA macro blocks from Internet applied to Office applications." -ForegroundColor Green

# 3. Disable OLE Package execution in Outlook (Policies and Preferences branches)
Set-UserRegDWord "software\policies\microsoft\office\16.0\outlook\security" "ShowOLEPackageObj" 0
Set-UserRegDWord "software\microsoft\office\16.0\outlook\security" "ShowOLEPackageObj" 0
Write-Host "[+] Outlook OLE Package execution blocked." -ForegroundColor Green
```

*To verify the current Office security settings:*

[Download Script: Get-OfficeSecurityStatus.ps1](audit_scripts/Get-OfficeSecurityStatus.ps1)

```powershell
# Get-OfficeSecurityStatus.ps1
# Description: Audits Microsoft Office macro settings and Outlook OLE package restrictions.

Write-Host "--- Auditing Microsoft Office Security Baseline ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper to audit registry values under HKCU
function Test-UserRegistryValue ($Path, $Name, $ExpectedValue) {
    $FullRegistryPath = "HKCU:\$Path"
    $Val = Get-ItemProperty -Path $FullRegistryPath -Name $Name -ErrorAction SilentlyContinue
    $Actual = if ($val) { $val.$Name } else { "" }
    $Color = "Red"
    if ($Actual -eq $ExpectedValue) {
        $Color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - User Registry: $Name | Actual: '$Actual' (Expected: '$ExpectedValue')" -ForegroundColor $Color
}

# 1. Audit macro signing warning
Test-UserRegistryValue "software\policies\microsoft\office\16.0\common\security" "vbawarnings" 3

# 2. Audit macro Internet blocks
$Apps = @("excel", "word", "powerpoint", "access", "visio")
foreach ($App in $Apps) {
    Test-UserRegistryValue "software\policies\microsoft\office\16.0\$App\security" "blockcontentexecutionfrominternet" 1
}

# 3. Audit Outlook OLE package block
Test-UserRegistryValue "software\policies\microsoft\office\16.0\outlook\security" "ShowOLEPackageObj" 0

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations on restricting application execution, blocking external scripts, and application sandboxing.
* **CIS Microsoft Office Benchmark**: Section on Office Common Security settings, VBA warnings, and blocking macros in internet files.
* **Microsoft Security Baseline**: Recommended settings for Microsoft Office and Office 365 ProPlus Security.
* **DoD Microsoft Outlook STIG**: Restrictions on active content, remote attachments, and OLE execution behavior.
