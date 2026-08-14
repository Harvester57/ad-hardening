# [REQ-END-176] Account Policy: Interactive Logon Security Options for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD` = `0` (REG_DWORD, Require CTRL+ALT+DEL enabled)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName` = `1` (REG_DWORD, Do not display last signed-in enabled)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CrashOnAuditFail` = `0` (REG_DWORD, Shut down system if unable to log audits disabled)

---

## Rationale
Configuring interactive logon behavior prevents credential harvesting via spoofed login screens and shoulder surfing:
* **Require CTRL+ALT+DEL (`DisableCAD = 0`)**: The Secure Attention Sequence (SAS / CTRL+ALT+DEL) can only be intercepted by the trusted Windows kernel/winlogon process, preventing malicious userland login prompts from capturing user credentials.
* **Hide Last Signed-in User (`DontDisplayLastUserName = 1`)**: Prevents shoulder-surfers or unauthorized observers from discovering valid username structures.
* **Do Not Crash on Audit Failure (`CrashOnAuditFail = 0`)**: Prevents sudden system shutdowns when the security event log fills, avoiding denial-of-service conditions.

---

## Legacy Impact & Compatibility
* **User Workflow**: Users must press CTRL+ALT+DEL and manually enter both their username and password/PIN during interactive logon.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Interactive logon: Do not require CTRL+ALT+DEL**: `Disabled` (value `0`)
   * **Interactive logon: Don't display last signed-in**: `Enabled` (value `1`)
   * **Audit: Shut down system immediately if unable to log security audits**: `Disabled` (value `0`)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountInteractiveLogon.ps1](../implementation_scripts/Configure-EndAccountInteractiveLogon.ps1)

```powershell
# Configure-EndAccountInteractiveLogon.ps1
Write-Host "Configuring Endpoint interactive logon security options..." -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPath)) { New-Item -Path $SystemPath -Force | Out-Null }

Set-ItemProperty -Path $SystemPath -Name "DisableCAD" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "CrashOnAuditFail" -Value 0 -Type DWord -Force

Write-Host "Interactive logon security options applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountInteractiveLogonStatus.ps1](../audit_scripts/Get-EndAccountInteractiveLogonStatus.ps1)

```powershell
# Get-EndAccountInteractiveLogonStatus.ps1
Write-Host "--- Auditing Endpoint Interactive Logon Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

function Test-RegVal ($Name, $Expected) {
    $Val = (Get-ItemProperty -Path $SystemPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal "DisableCAD" 0
Test-RegVal "DontDisplayLastUserName" 1
Test-RegVal "CrashOnAuditFail" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.2.2 (CrashOnAuditFail), Section 2.3.7.1 (DisableCAD), Section 2.3.7.2 (DontDisplayLastUserName)
* **ANSSI AD Hardening Guide**: Recommendations on secure desktop and interactive logon hardening
* **DoD Windows 11 Computer STIG v2r6**: SAS CTRL+ALT+DEL and username display restrictions
