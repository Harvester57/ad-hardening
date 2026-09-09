# [REQ-END-188] Administrative Templates: Logon Display and Credential Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-177](../../07-paws/admin-templates/configure-paw-at-logon-display-options.md); for Domain Controllers, refer to [REQ-DC-024](../../02-domain-controllers/configure-security-options.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Block user from showing account details on sign-in**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Block user from showing account details on sign-in` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `BlockUserFromShowingAccountDetailsOnSignin`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Do not display network selection UI**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Do not display network selection UI` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `DontDisplayNetworkSelectionUI`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Do not enumerate connected users on domain-joined computers**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Do not enumerate connected users on domain-joined computers` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `DontEnumerateConnectedUsers`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Turn off app notifications on the lock screen**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Turn off app notifications on the lock screen` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `DisableLockScreenAppNotifications`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Turn off picture password sign-in**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Turn off picture password sign-in` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `BlockDomainPicturePassword`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Turn on convenience PIN sign-in**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Turn on convenience PIN sign-in` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `AllowDomainPINLogon`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Prevent the use of security questions for local accounts**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Prevent the use of security questions for local accounts` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
    * Value Name: `NoLocalPasswordResetQuestions`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled)
  * **Configure transmission of user password in MPR notifications**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Logon\Configure the transmission of the user's password in the content of MPR notifications sent by winlogon` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `EnableMPR`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)

---

## Rationale
The Windows logon desktop and lock screen represent the physical perimeter of the operating system. In unhardened configurations, the logon interface exposes critical internal network information, leaks corporate usernames, presents weak authentication alternatives, and permits unauthorized network reconfigurations without authentication.

### 1. Eliminating Lock Screen Reconnaissance and Identity Harvesting
By default, the Windows lock screen displays the identity of the previously authenticated user or enumerates all active sessions:
* **Account Name and Email Harvesting**: Displaying user names, email addresses, and account pictures allows physical bystanders, building visitors, or surveillance cameras to harvest valid enterprise logon names and administrative IDs.
* **Enumeration of Signed-In Users**: When multiple users share a machine, Fast User Switching displays account tiles for every connected user.
* Enforcing `BlockUserFromShowingAccountDetailsOnSignin = 1` and `DontEnumerateConnectedUsers = 1` strips personal identifiers from the lock screen, presenting an uninformative, generic authentication prompt that requires manual entry of the username and password.

### 2. Guarding the Lock Screen Network Boundary
The lock screen provides a network flyout control in the lower-right corner:
* **Rogue Network Redirection**: Anyone with physical access to an unattended, locked workstation can click the network icon to disconnect the machine from the corporate LAN/Wi-Fi and connect it to an untrusted rogue Wi-Fi access point (such as an "Evil Twin" or cellular hotspot).
* **Adversary-in-the-Middle Positioning**: Once connected to an attacker-controlled network, the attacker can poison DNS, initiate NTLM credential harvesting against background services, or attempt network exploits against open listening ports before the user ever unlocks the desktop.
* Setting `DontDisplayNetworkSelectionUI = 1` completely removes the network flyout from the lock screen, preventing unauthenticated network switching.

### 3. Preventing Data Leakage via Lock Screen Toast Notifications
Toast notifications from productivity applications (Outlook, Teams, messaging platforms) frequently display snippet previews above the lock screen barrier:
* Notifications often reveal sensitive business discussions, meeting invitations, and two-factor authentication (2FA) verification codes or SMS OTPs.
* Setting `DisableLockScreenAppNotifications = 1` suppresses all lock screen toast notifications, ensuring message content is only visible after successful interactive authentication.

### 4. Prohibiting Weak Authentication and Credential Overrides
Consumer-grade authentication mechanisms undermine enterprise Kerberos and PKI standards:
* **Picture Passwords (`BlockDomainPicturePassword = 1`)**: Feature low entropy, are susceptible to smudge analysis on touchscreen devices, and can be trivially observed through shoulder surfing.
* **Convenience PINs (`AllowDomainPINLogon = 0`)**: Convenience PINs store cached credential hashes on the local disk without TPM-backed cryptographic hardware binding or hardware rate-limiting. *(Note: This does not affect Windows Hello for Business, which utilizes asymmetric keys sealed in the TPM 2.0 module and is governed under dedicated WHfB policies).*
* **Security Questions (`NoLocalPasswordResetQuestions = 1`)**: Password reset questions rely on static trivia easily discoverable via open-source intelligence (OSINT) and social engineering.
* **MPR Notification Password Suppression (`EnableMPR = 0`)**: Disables passing cleartext passwords inside Multiple Provider Router notifications from Winlogon to third-party network providers.

### 5. MITRE ATT&CK Mapping
* **T1087.001 - Account Discovery: Local Account**: Discovery of valid usernames on lock screens.
* **T1040 - Network Sniffing**: Diverting locked hosts to rogue wireless networks to capture traffic.
* **T1110.001 - Brute Force: Password Guessing**: Exploiting weak convenience PINs or predictable security questions.
* **T1552.001 - Unsecured Credentials: Credentials In Files / Memory**: Intercepting cleartext MPR notifications.

---

## Legacy Impact & Compatibility
* **Interactive Logon Experience**: Users must type their full username and password or insert their smartcard. Account tiles and pictures will not appear automatically.
* **Network Roaming for Mobile Users**: Laptops traveling between known networks will connect automatically to pre-configured corporate SSIDs. If an end user needs to join a new hotel or public Wi-Fi network, they must log in using cached credentials before associating with the network in the desktop tray.
* **Windows Hello for Business**: Enterprise WHfB PIN and biometric authentication remain fully operational when deployed via Microsoft Intune or Group Policy WHfB templates.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Logon`
  * **Block user from showing account details on sign-in**: Set to `Enabled`
  * **Do not display network selection UI**: Set to `Enabled`
  * **Do not enumerate connected users on domain-joined computers**: Set to `Enabled`
  * **Turn off app notifications on the lock screen**: Set to `Enabled`
  * **Turn off picture password sign-in**: Set to `Enabled`
  * **Turn on convenience PIN sign-in**: Set to `Disabled`
  * **Prevent the use of security questions for local accounts**: Set to `Enabled`
  * **Configure the transmission of the user's password in the content of MPR notifications sent by winlogon**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtLogonDisplayOptions.ps1](../implementation_scripts/Configure-EndAtLogonDisplayOptions.ps1)

```powershell
#Configure-EndAtLogonDisplayOptions.ps1
# Description: Configures Administrative Templates: Logon Display and Credential Restrictions.

Write-Host "Configuring Administrative Templates: Logon Display and Credential Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableMPR" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Logon Display and Credential Restrictions applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtLogonDisplayOptionsStatus.ps1](../audit_scripts/Get-EndAtLogonDisplayOptionsStatus.ps1)

```powershell
#Get-EndAtLogonDisplayOptionsStatus.ps1
# Description: Audits Administrative Templates: Logon Display and Credential Restrictions.

Write-Host "--- Auditing Administrative Templates: Logon Display and Credential Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "BlockUserFromShowingAccountDetailsOnSignin"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "DontDisplayNetworkSelectionUI"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "DontEnumerateConnectedUsers"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "DisableLockScreenAppNotifications"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "BlockDomainPicturePassword"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "AllowDomainPINLogon"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "NoLocalPasswordResetQuestions"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "EnableMPR"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.28.1, 18.9.28.2, 18.9.28.3, 18.9.28.5, 18.9.28.6, 18.9.28.7, 18.10.15.3, 18.10.82.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.28.1, 18.9.28.2, 18.9.28.3, 18.9.28.5, 18.9.28.6, 18.9.28.7, 18.10.15.3, 18.10.82.1
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000075, WN10-CC-000080, WN10-CC-000085, WN10-CC-000090
* **ANSSI Active Directory Hardening Guide**: Section 3.1 (Securing interactive logon prompts and disabling unauthenticated lock screen features)
* **Microsoft Security Baseline**: Windows Client Security Baseline (Logon and Credential Protections)
