# [REQ-ID-016] Configure Logon Screen and Credentials Delegation

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Logon screen local users enumeration GPO**: `Computer Configuration\Policies\Administrative Templates\System\Logon\Enumerate local users on domain-joined computers` -> Disabled
  * **CredSSP Encryption GPO**: `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Encryption Oracle Remediation` -> Enabled (Select **Force Updated Clients** in options)
  * **Protected Credentials Delegation GPO**: `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Remote host allows delegation of non-exportable credentials` -> Enabled
  * **Registry Location (Logon)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` -> `EnumerateLocalUsers` = `0` (REG_DWORD)
  * **Registry Location (CredSSP)**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters` -> `AllowEncryptionOracle` = `0` (REG_DWORD)
  * **Registry Location (Credentials Delegation)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation` -> `AllowProtectedCreds` = `1` (REG_DWORD)

---

## Rationale
Securing interactive logons and connection pathways is critical to preventing identity leaks, unauthorized physical user identification, and credential theft during remote administration:

1. **Logon Screen Reconnaissance**: Allowing the local login screen to enumerate local and domain users exposes valid usernames to physical shoulder-surfers or unauthorized operators. Disabling local user enumeration hides username lists at logon.
2. **CredSSP Vulnerabilities (CVE-2018-0886)**: The Credential Security Support Provider protocol (CredSSP) had a logical remote code execution flaw. Enforcing Encryption Oracle Remediation in updated mode blocks connections from unpatched clients and servers.
3. **Delegated Credential Extraction**: When users connect to remote hosts, delegating exportable credentials exposes their authentication materials in remote LSASS memory. Forcing the delegation of non-exportable credentials ensures authentication materials cannot be exported by administrative attackers on the remote system.

---

## Legacy Impact & Compatibility
* **CredSSP Connection Failures**: Administrative RDP sessions to legacy, unpatched servers (e.g., Windows Server 2008 / Windows Server 2003) will be blocked if those targets do not support patched CredSSP. These targets must be decommissioned or patched.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Disable Logon Screen Username Enumeration
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to your computer OUs (e.g., `GPO_Computer_Hardening_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Logon`
4. Double-click **Enumerate local users on domain-joined computers**.
5. Set it to **Disabled** and click **OK**.

#### 2. Configure CredSSP and Credentials Delegation
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation`
2. Double-click **Encryption Oracle Remediation**.
3. Set it to **Enabled**, and select **Force Updated Clients** in the options dropdown. Click **OK**.
4. Double-click **Remote host allows delegation of non-exportable credentials**.
5. Set it to **Enabled** and click **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply logon screen and delegation settings to the registry.

[Download Script: Configure-CredentialDelegationAndLogon.ps1](implementation_scripts/Configure-CredentialDelegationAndLogon.ps1)

```powershell
# Configure-CredentialDelegationAndLogon.ps1
# Description: Hardens logon screen user enumeration, CredSSP encryption oracle remediation, and remote host non-exportable credentials delegation.

Write-Host "Applying logon screen and credentials delegation registry controls..." -ForegroundColor Cyan

# 1. Disable Logon Screen User Enumeration
$SystemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPath -Name "EnumerateLocalUsers" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Logon screen local user enumeration disabled." -ForegroundColor Green

# 2. Enforce CredSSP Encryption Oracle Remediation
$CredSspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $CredSspPath)) {
    New-Item -Path $CredSspPath -Force | Out-Null
}
Set-ItemProperty -Path $CredSspPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] CredSSP Encryption Oracle Remediation configured to Force Updated Clients." -ForegroundColor Green

# 3. Remote Host Allows Delegation of Non-Exportable Credentials
$DelegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if (-not (Test-Path $DelegPath)) {
    New-Item -Path $DelegPath -Force | Out-Null
}
Set-ItemProperty -Path $DelegPath -Name "AllowProtectedCreds" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Delegation of non-exportable credentials enabled." -ForegroundColor Green
```

*To audit these logon screen and delegation settings:*

[Download Script: Get-CredentialDelegationAndLogonStatus.ps1](audit_scripts/Get-CredentialDelegationAndLogonStatus.ps1)

```powershell
# Get-CredentialDelegationAndLogonStatus.ps1
# Description: Audits registry configuration of user enumeration, CredSSP, and delegation settings.

Write-Host "--- Auditing Credentials Delegation and Logon Settings ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to check registry settings
function Confirm-RegValue ($Path, $Name, $Expected) {
    if (Test-Path $Path) {
        $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        $Val = $Reg.$Name
        if ($Val -eq $Expected) {
            Write-Host "  [+] Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] NOT FOUND: Path $($Path) (Expected: $Name = $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 1. User Enumeration
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" 0

# 2. CredSSP AllowEncryptionOracle
Confirm-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" 0

# 3. Protected Credentials Delegation
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" 1

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
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.8 (Credentials Delegation)
* **ANSSI AD Hardening Guide**: Security guidelines regarding credential delegation and local machine access configuration.
* **Microsoft Security Guidance**: Mitigating CredSSP vulnerabilities (CVE-2018-0886)
