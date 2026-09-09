# [REQ-PAW-177] Administrative Templates: Logon Display and Credential Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-188](../../08-endpoints/admin-templates/configure-end-at-logon-display-options.md); for Domain Controllers, refer to [REQ-DC-024](../../02-domain-controllers/configure-security-options.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) serve as the dedicated management perimeter for Active Directory Domain Controllers and enterprise tier-0 administrative roles. Visual information disclosure, network re-association controls at lock screen, and consumer authentication features introduce critical exposure to administrative credential theft and physical exploitation.

### 1. Absolute Lock Screen Visual Confidentiality on Tier 0 Hosts
Exposing administrative account identifiers creates severe physical intelligence leakage:
* Displaying usernames, email addresses, or avatars of Tier 0 administrators (such as members of Domain Admins or Enterprise Admins) allows observers to map administrative accounts and target them with social engineering or spear-phishing.
* Fast User Switching tiles reveal active administrative sessions.
* Enforcing `BlockUserFromShowingAccountDetailsOnSignin = 1` and `DontEnumerateConnectedUsers = 1` strips all personal identifiers from the logon screen. Administrators must explicitly type their full administrative credentials.

### 2. Guarding the PAW Management Network Boundary
The lock screen network selection flyout allows physical interaction with the host's network state:
* An attacker with temporary physical proximity could disconnect the PAW from the secure management VLAN and connect it to a rogue access point or malicious cellular hotspot.
* Once diverted, the attacker could poison local DNS or capture administrative NTLM handshakes initiated by background services.
* Enforcing `DontDisplayNetworkSelectionUI = 1` removes the network selection interface entirely from the lock screen.

### 3. Preventing Data Leakage via Notifications
Administrative alerts, security operational notifications, or multi-factor authentication (MFA) verification codes displayed on the lock screen can be viewed by unauthorized observers:
* Enforcing `DisableLockScreenAppNotifications = 1` guarantees that all notification content is suppressed until the operator successfully authenticates.

### 4. Prohibiting Substandard Authentication Mechanisms
Tier 0 administrative access requires cryptographic authentication:
* **Picture Passwords & Convenience PINs**: Picture passwords and non-TPM convenience PINs lack hardware attestation and brute-force resistance. They are strictly prohibited on PAWs. (Hardware-backed Smart Cards and TPM 2.0-bound Windows Hello for Business remain fully supported).
* **Security Questions**: Local account security questions provide trivial password bypasses and must be eliminated via `NoLocalPasswordResetQuestions = 1`.
* **MPR Notifications**: Passing cleartext passwords in Multiple Provider Router notifications exposes credentials in memory and must be disabled (`EnableMPR = 0`).

### 5. MITRE ATT&CK Mapping
* **T1087.001 - Account Discovery: Local Account**: Harvesting Tier 0 administrator accounts displayed on the lock screen.
* **T1040 - Network Sniffing**: Diverting locked PAWs to rogue Wi-Fi networks to intercept management traffic.
* **T1110.001 - Brute Force: Password Guessing**: Bypassing strong authentication via convenience PINs or security questions.
* **T1552.001 - Unsecured Credentials: Credentials In Files / Memory**: Intercepting cleartext MPR notifications.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Operators must type their full username and password or authenticate using their hardware smartcard.
* **Network Management**: PAW hardware connects exclusively to authorized wired management switchports or dedicated, certificate-authenticated enterprise Wi-Fi networks. Unauthenticated wireless switching is blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
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

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtLogonDisplayOptions.ps1](../implementation_scripts/Configure-PawAtLogonDisplayOptions.ps1)

```powershell
#Configure-PawAtLogonDisplayOptions.ps1
# Description: Configures Administrative Templates: Logon Display and Credential Restrictions for PAWs.

Write-Host "Configuring Administrative Templates: Logon Display and Credential Restrictions for PAWs..." -ForegroundColor Cyan

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

Write-Host "[+] Administrative Templates: Logon Display and Credential Restrictions for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtLogonDisplayOptionsStatus.ps1](../audit_scripts/Get-PawAtLogonDisplayOptionsStatus.ps1)

```powershell
#Get-PawAtLogonDisplayOptionsStatus.ps1
# Description: Audits Administrative Templates: Logon Display and Credential Restrictions for PAWs.

Write-Host "--- Auditing Administrative Templates: Logon Display and Credential Restrictions for PAWs ---" -ForegroundColor Cyan
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
* **Microsoft Privileged Access Workstation Guidance**: PAW Visual Confidentiality and Physical Host Hardening
