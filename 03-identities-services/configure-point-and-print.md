# Hardening Requirement: Configure Point and Print, ELAM, Logon Screen, and Credentials Delegation

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Point and Print GPO**: `Computer Configuration\Policies\Administrative Templates\Printers\Limits print driver installation to Administrators` -> Enabled
  * **Early Launch Antimalware (ELAM) GPO**: `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy` -> Enabled (Select **Good, unknown and bad but critical** in options)
  * **Logon screen local users enumeration GPO**: `Computer Configuration\Policies\Administrative Templates\System\Logon\Enumerate local users on domain-joined computers` -> Disabled
  * **CredSSP Encryption GPO**: `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Encryption Oracle Remediation` -> Enabled (Select **Force Updated Clients** in options)
  * **Protected Credentials Delegation GPO**: `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Remote host allows delegation of non-exportable credentials` -> Enabled
  * **Registry Location (Printers)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint` -> `RestrictDriverInstallationToAdministrators` = `1` (REG_DWORD)
  * **Registry Location (ELAM)**: `HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch` -> `DriverLoadPolicy` = `3` (REG_DWORD)
  * **Registry Location (Logon)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` -> `EnumerateLocalUsers` = `0` (REG_DWORD)
  * **Registry Location (CredSSP)**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters` -> `AllowEncryptionOracle` = `0` (REG_DWORD)
  * **Registry Location (Credentials Delegation)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation` -> `AllowProtectedCreds` = `1` (REG_DWORD)

---

## Rationale
Ensuring robust endpoint security and credential isolation requires configurations that address printer drivers, early boot processes, credential delegation, and the local login screen.

Hardening these features mitigates the following vulnerabilities:
1. **PrintNightmare (CVE-2021-34527 / CVE-2021-1675)**: Point and Print features historically allowed non-administrative users to download and install printer drivers from arbitrary network print servers. Attackers exploited this to inject malicious DLLs, obtaining local SYSTEM execution. Restricting print driver installation to Administrators blocks this privilege escalation path.
2. **Early Boot Rootkits**: Malicious boot-start drivers can run before security software initializes. Configuring Early Launch Antimalware (ELAM) driver policies ensures that unknown or malicious boot drivers are blocked from executing.
3. **Logon Screen Reconnaissance**: Allowing the local login screen to enumerate local and domain users exposes valid usernames to physical shoulder-surfers or unauthorized operators. Disabling local user enumeration hides username lists at logon.
4. **CredSSP Vulnerabilities (CVE-2018-0886)**: The Credential Security Support Provider protocol (CredSSP) had a logical remote code execution flaw. Enforcing Encryption Oracle Remediation in updated mode blocks connections from unpatched clients and servers.
5. **Delegated Credential Extraction**: When users connect to remote hosts, delegating exportable credentials exposes their authentication materials in remote LSASS memory. Forcing the delegation of non-exportable credentials ensures authentication materials cannot be exported by administrative attackers on the remote system.

---

## Legacy Impact & Compatibility
* **Network Printer Deployments**: Non-administrative users will be blocked from connecting to shared network printers unless the corresponding drivers have been pre-installed or pre-staged by an administrator using tools like Print Management.
* **Boot-Start Drivers**: If legitimate, custom, unsigned kernel drivers are active on the host, the ELAM policy may block them from loading during boot, causing blue screen (BSOD) failures. Ensure all active drivers are digitally signed and verified prior to applying this policy.
* **CredSSP Connection Failures**: Administrative RDP sessions to legacy, unpatched servers (e.g., Windows Server 2008 / Windows Server 2003) will be blocked if those targets do not support patched CredSSP. These targets must be decommissioned or patched.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Limit Print Driver Installation
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to your computer OUs (e.g., `GPO_Computer_Hardening_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Printers`
4. Double-click **Limits print driver installation to Administrators**.
5. Set it to **Enabled** and click **OK**.

#### 2. Configure ELAM Boot Driver Policy
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware`
2. Double-click **Boot-Start Driver Initialization Policy**.
3. Set it to **Enabled**.
4. In the options dropdown, select **Good, unknown and bad but critical** (corresponds to registry value `3`).
5. Click **OK**.

#### 3. Disable Logon Screen Username Enumeration
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Logon`
2. Double-click **Enumerate local users on domain-joined computers**.
3. Set it to **Disabled** and click **OK**.

#### 4. Configure CredSSP and Credentials Delegation
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation`
2. Double-click **Encryption Oracle Remediation**.
3. Set it to **Enabled**, and select **Force Updated Clients** in the options dropdown. Click **OK**.
4. Double-click **Remote host allows delegation of non-exportable credentials**.
5. Set it to **Enabled** and click **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply the printers, boot drivers, logon screen, and delegation settings to the registry.

```powershell
# Set-EndpointDelegationAndBootHardening.ps1
# Description: Hardens Point and Print restrictions, ELAM policies, logon screen enumeration, and credentials delegation.

Write-Host "Applying printer, boot driver, logon screen, and delegation registry controls..." -ForegroundColor Cyan

# 1. Limit Print Driver Installation to Administrators
$PrinterPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $PrinterPath)) {
    New-Item -Path $PrinterPath -Force | Out-Null
}
Set-ItemProperty -Path $PrinterPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Print driver installation restricted to Administrators." -ForegroundColor Green

# 2. Configure ELAM Driver Load Policy
$ElamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $ElamPath)) {
    New-Item -Path $ElamPath -Force | Out-Null
}
Set-ItemProperty -Path $ElamPath -Name "DriverLoadPolicy" -Value 3 -Type DWord -ErrorAction Stop
Write-Host "[+] ELAM Boot-Start driver initialization policy set to Good, unknown and bad but critical." -ForegroundColor Green

# 3. Disable Logon Screen User Enumeration
$SystemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPath -Name "EnumerateLocalUsers" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Logon screen local user enumeration disabled." -ForegroundColor Green

# 4. Enforce CredSSP Encryption Oracle Remediation
$CredSspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $CredSspPath)) {
    New-Item -Path $CredSspPath -Force | Out-Null
}
Set-ItemProperty -Path $CredSspPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] CredSSP Encryption Oracle Remediation configured to Force Updated Clients." -ForegroundColor Green

# 5. Remote Host Allows Delegation of Non-Exportable Credentials
$DelegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if (-not (Test-Path $DelegPath)) {
    New-Item -Path $DelegPath -Force | Out-Null
}
Set-ItemProperty -Path $DelegPath -Name "AllowProtectedCreds" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Delegation of non-exportable credentials enabled." -ForegroundColor Green
```

*To audit these printers, boot drivers, logon screen, and delegation settings:*
```powershell
# Get-EndpointDelegationAndBootStatus.ps1
# Description: Audits registry configuration of Point and Print, ELAM, user enumeration, and delegation.

Write-Host "--- Auditing Endpoint Delegation and Boot Settings ---" -ForegroundColor Cyan

# Helper function to check registry settings
function Confirm-RegValue ($Path, $Name, $Expected) {
    if (Test-Path $Path) {
        $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        $Val = $Reg.$Name
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor $Color
    } else {
        Write-Host "    - Path $($Path): NOT FOUND" -ForegroundColor Red
    }
}

# 1. Point and Print
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators" 1

# 2. ELAM Policy
Confirm-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" 3

# 3. User Enumeration
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" 0

# 4. CredSSP AllowEncryptionOracle
Confirm-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" 0

# 5. Protected Credentials Delegation
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" 1
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.2.1 (Printers), Section 18.2.2 (System Options / ELAM), Section 18.8 (Credentials Delegation)
* **ANSSI AD Hardening Guide**: Security guidelines regarding printer service vulnerabilities (PrintNightmare) and local machine access configuration.
* **Microsoft Security Guidance**: Mitigating PrintNightmare and CredSSP vulnerabilities (CVE-2018-0886)
