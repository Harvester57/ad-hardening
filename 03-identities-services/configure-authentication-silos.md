# [REQ-ID-012] Configure Active Directory Authentication Silos and Policies

## Target Scope
* **Applicable Systems**: Domain Controllers, Tier 0 Administration Workstations (PAWs), Tier 0 Administrator Accounts, Tier 0 Managed Service Accounts (gMSAs)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025, Windows 10 Enterprise / Pro (1809+), Windows 11 Enterprise / Pro

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Active Directory Configuration Partition Paths**:
    * Silos: `CN=AuthN Silos,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=[Domain]` (objectClass: `msDS-AuthNPolicySilo`)
    * Policies: `CN=AuthN Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=[Domain]` (objectClass: `msDS-AuthNPolicy`)
  * **KDC GPO Policy (Domain Controllers)**:
    * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\KDC`
    * **Policy**: `KDC support for claims, compound authentication and Kerberos armoring` -> Enabled (`Supported` or `Always provide claims`)
    * **Registry Location**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters`
      * `EnableCbacAndArmor` = `1` (REG_DWORD)
      * `CbacAndArmorLevel` = `1` (REG_DWORD)
  * **Kerberos Client GPO Policy (Domain Controllers, PAWs, Tier 0 Hosts)**:
    * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
    * **Policy**: `Kerberos client support for claims, compound authentication and Kerberos armoring` -> Enabled
    * **Registry Location**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`
      * `EnableCbacAndArmor` = `1` (REG_DWORD)
  * **Audit Event Logging Channels**:
    * **Operational Channel**: `Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational`
    * **Security Log Events**: Event IDs 4768 (TGT Request), 4769 (TGS Request), 4771 (Pre-Authentication Failed)

---

## Rationale
Standard Active Directory access control models rely on Discretionary Access Control Lists (DACLs) and security group memberships. While DACLs determine which directory objects or network shares an administrative account can modify, they do not restrict the physical or virtual systems from which that administrator can log on.

In an active enterprise network, if a Tier 0 administrator (such as a Domain Admin or Enterprise Admin) authenticates from or logs on to a compromised Tier 1 server (e.g., an application host) or a Tier 2 workstation (e.g., a standard user workstation), their authentication material is loaded into the memory of the Local Security Authority Subsystem Service (LSASS). Attackers with local administrative control over that lower-tier system can scrape LSASS memory using credential-harvesting tools (such as Mimikatz) to extract Kerberos Ticket Granting Tickets (TGTs), NTLM password hashes, or plaintext credentials, resulting in total forest compromise via lateral movement and privilege escalation (Pass-the-Hash, Pass-the-Ticket).

Authentication Policies and Authentication Policy Silos (introduced in Windows Server 2012 R2) provide cryptographic containment enforced directly at the Key Distribution Center (KDC) on Domain Controllers:

1. **Cryptographic Boundary Enforcement at KDC**:
   Unlike host-level software restrictions or traditional group memberships, Authentication Silos are evaluated by the KDC during the Kerberos ticket acquisition phase (AS-REQ and TGS-REQ). When an account assigned to an Authentication Policy Silo requests a Kerberos ticket, the KDC inspects the client host's device claims (`@Device.ad:silo`). If the host is not enrolled in the same silo, the KDC unconditionally rejects ticket issuance with the Kerberos status code `KDC_ERR_POLICY` (`0x12`). Because ticket issuance is denied at the domain controller level, administrative credentials are never exposed, transmitted, or cached on unauthorized workstations.

2. **Dynamic Access Control (DAC) & Compound Authentication**:
   Authentication Silos leverage Dynamic Access Control (DAC) device claims. When accounts are enrolled in a silo, Active Directory automatically issues the `@Device.ad:silo` claim during Kerberos authentication. Enabled by Kerberos Flexible Authentication Secure Tunneling (FAST / RFC 6113), the KDC evaluates compound authentication, validating both the user identity and the computer identity simultaneously against conditional Security Descriptor Definition Language (SDDL) rules such as `O:SYG:SYD:(XA;;CR;;;WD;(@Device.ad:silo == "T0_Silo"))`.

3. **Restricted Kerberos TGT Lifetimes**:
   Authentication Policies enforce reduced Kerberos Ticket Granting Ticket (TGT) lifetimes (e.g., 120 minutes / 2 hours) specifically on high-privilege silo accounts, without impacting standard domain users whose default TGT lifetime remains 10 hours. This significantly constrains the window of opportunity for ticket reuse attacks or stolen session ticket exploitation.

4. **Defense-in-Depth Architectural Triad**:
   Authentication Silos form an inseparable architectural defense triad with the **Protected Users** security group (REQ-ID-005), **Kerberos Armoring (FAST)** (REQ-DC-013, REQ-PAW-013, REQ-END-013), and **Privileged Access Workstations** (PAWs). Together, these controls prevent credential dumping, halt NTLM fallback, and enforce strict Tier 0 cryptographic isolation.

---

## Legacy Impact & Compatibility
* **Mandatory Protected Users Group Membership (NTLM Bypass Mitigation)**:
  Authentication Policies and Silos are enforced *exclusively* within the Kerberos protocol. The KDC cannot apply silo restrictions to legacy NTLM authentication exchanges (processed through Netlogon and NTLMSSP). If an attacker forces an NTLM authentication challenge from an unapproved system, or if an administrator uses an application that falls back to NTLM, silo containment is completely bypassed. Consequently, every user account placed in an Authentication Policy Silo **must** also be added to the **Protected Users** security group (`CN=Protected Users,CN=Users,DC=[Domain]`) or have NTLM explicitly blocked domain-wide. The Protected Users group prevents NTLM hash caching, prohibits NTLM authentication, bans weak DES/RC4 ciphers, and disables credential delegation.
* **Domain & Forest Functional Level**:
  The Active Directory forest and domain functional level must be configured to at least **Windows Server 2012 R2**.
* **Domain Controller Enrollment Requirement**:
  All writable Domain Controllers in the domain **must** be enrolled as members of the Tier 0 Silo (`T0_Silo`). Domain Controllers act as Kerberos clients when authenticating to each other for Active Directory replication, KDC referral tickets, and directory management RPC calls. If writable Domain Controllers are not enrolled in the silo, intra-DC replication and directory services can experience critical failures.
* **Single Silo Assignment Constraint**:
  An Active Directory object (user, computer, or service account) can belong to **only one** Authentication Policy Silo at any time. The underlying Active Directory attribute `msDS-AuthNPolicySilo` is a single-valued Distinguished Name. Adding an account to a new silo automatically removes it from its previously assigned silo. Organizations implementing tiered administrative models must establish distinct, separate silos for Tier 0, Tier 1, and Tier 2 assets.
* **Kerberos Armoring (FAST) Requirement on Client Workstations**:
  All PAWs and management hosts must have Kerberos client support for claims and armoring enabled (`EnableCbacAndArmor = 1`). If client armoring is not enabled on a PAW, the host cannot provide device claims to the KDC, causing valid Tier 0 administrator logon attempts from that PAW to be rejected by the Domain Controller.
* **Staged Rollout & Audit Mode Strategy**:
  Enforcing a silo without baseline verification risks locking out administrators if legitimate management hosts or service accounts were omitted. Always deploy Authentication Policies and Silos in **Audit Mode** (`-Enforce $false`) first. While in audit mode, authentication requests violating policy boundaries are permitted, but detailed failure events are logged to `Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational`:
  * **Event ID 16867**: User authentication policy failure (Audit mode).
  * **Event ID 16868**: Authentication policy silo failure (Audit mode).
  * **Event ID 16871**: Computer authentication policy failure (Audit mode).
  * **Event ID 16873**: Service authentication policy failure (Audit mode).
  Monitor these events for at least 14 to 30 days during normal administrative operations before switching the policy and silo to Enforced Mode (`-Enforce $true`).

---

## Implementation Steps

### Option A: Group Policy & Active Directory Administrative Center (ADAC) Configuration (Preferred)

#### 1. Enable KDC Claims and Armoring on Domain Controllers via GPO
Before configuring silos, Domain Controllers must be configured to support claims and Kerberos armoring:

1. Open **Group Policy Management** (`gpmc.msc`).
2. Edit the GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\KDC`
4. Double-click **KDC support for claims, compound authentication and Kerberos armoring**.
5. Set it to **Enabled**.
6. Under options, select **Supported** (or **Always provide claims**).
7. Save the GPO and run `gpupdate /force` on all Domain Controllers.

#### 2. Enable Kerberos Client Support on PAWs and Domain Controllers via GPO
All Tier 0 PAWs and Domain Controllers must be configured to assert client claims:

1. Edit the GPO linked to the **Privileged Access Workstations** OU and the **Domain Controllers** OU.
2. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
3. Double-click **Kerberos client support for claims, compound authentication and Kerberos armoring**.
4. Set it to **Enabled**.
5. Save the GPO and run `gpupdate /force` on target systems.

#### 3. Enable Operational Event Logging on Domain Controllers
On each Domain Controller, enable the operational log channel to capture audit events:

1. Open an elevated command prompt on the Domain Controller.
2. Execute:
   ```cmd
   wevtutil sl Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational /e:true
   ```

#### 4. Create the Authentication Policy in ADAC (Staging / Audit Mode)
1. Open **Active Directory Administrative Center** (`dsac.exe`) on a Domain Controller or PAW.
2. In the left navigation pane, switch to the **Tree View**, expand the domain, and select the **Authentication** container.
3. Right-click **Authentication Policies**, select **New**, and click **Authentication Policy**:
   * **Name**: `T0_AuthPol`
   * **Description**: `Authentication Policy for Tier 0 Isolation`
   * Under **User**:
     * Check **Enforce user ticket lifetime restrictions** and enter `120` minutes.
     * Check **User Allowed To Authenticate From**, click **Edit**, click **Add a condition**, and specify:
       `Device` `ad:silo` `Equals` `Value` `T0_Silo`
     * Under **Policy setting**, leave **Audit policy restrictions** selected during the initial deployment phase.
   * Under **Computer**:
     * Check **Enforce computer ticket lifetime restrictions** and enter `120` minutes.
   * Under **Service**:
     * Check **Enforce service ticket lifetime restrictions** and enter `120` minutes.
4. Click **OK** to save the policy.

#### 5. Create the Authentication Policy Silo in ADAC
1. In the **Authentication** container, right-click **Authentication Policy Silos**, select **New**, and click **Authentication Policy Silo**:
   * **Name**: `T0_Silo`
   * **Description**: `Authentication Policy Silo for Tier 0 Containment`
   * Under **Permitted Accounts**, click **Add** to specify:
     * All Tier 0 Administrator user accounts.
     * All Tier 0 Privileged Access Workstations (PAWs).
     * All writable Domain Controllers in the domain.
   * Under **Authentication Policies**:
     * **User**: Select `T0_AuthPol`.
     * **Computer**: Select `T0_AuthPol`.
     * **Service**: Select `T0_AuthPol`.
   * Under **Silo setting**, select **Audit silo policies** during initial staging.
2. Click **OK** to create the silo.

#### 6. Validate Staging Logs and Switch to Enforced Mode
1. After running the silo in Audit Mode for 14 to 30 days, review Event Viewer on Domain Controllers under:
   `Applications and Services Logs\Microsoft\Windows\Authentication\AuthenticationPolicyFailures-DomainController\Operational`
2. Confirm that no legitimate administrative workflows generate Event IDs 16867 or 16868.
3. Confirm that all enrolled Tier 0 administrative users are members of the **Protected Users** group (`CN=Protected Users,CN=Users,DC=[Domain]`).
4. Re-open **Active Directory Administrative Center** (`dsac.exe`).
5. Open `T0_AuthPol` and change the policy setting to **Enforce policy restrictions**.
6. Open `T0_Silo` and change the silo setting to **Enforce the silo policies**.
7. Click **OK** to apply full cryptographic enforcement.

---

### Option B: PowerShell Configuration (Remediation / Non-GPO)

Run the following script to configure local KDC registry settings, enable the operational event log channel, create the Tier 0 Authentication Policy with device claim restrictions, create the Silo, and enroll Domain Controllers, PAWs, and administrators.

By default, the script deploys in **Audit Mode** to prevent accidental lockouts. Specify the `-Enforce` switch parameter once staging and logging validation are complete.

[Download Script: Set-ADAuthenticationSilo.ps1](implementation_scripts/Set-ADAuthenticationSilo.ps1)

```powershell
# Set-ADAuthenticationSilo.ps1
# Description: Configures Active Directory Authentication Policies and Silos for Tier 0 isolation.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Enforce,

    [Parameter(Mandatory = $false)]
    [string]$PolicyName = "T0_AuthPol",

    [Parameter(Mandatory = $false)]
    [string]$SiloName = "T0_Silo",

    [Parameter(Mandatory = $false)]
    [string]$UserGroupName = "Grp_Tier0_Admins",

    [Parameter(Mandatory = $false)]
    [string]$ComputerGroupName = "Grp_Tier0_PAWs",

    [Parameter(Mandatory = $false)]
    [int]$UserTGTLifetimeMins = 120
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Applying hardening requirement: Configure Active Directory Authentication Silos..." -ForegroundColor Cyan

# 1. Validate Domain Functional Level
$domain = Get-ADDomain -ErrorAction Stop
if ($domain.DomainMode -lt [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2012R2Domain) {
    Write-Error "Active Directory Domain Functional Level must be Windows Server 2012 R2 or higher. Current DFL: $($domain.DomainMode)"
    return
}

# 2. Configure KDC and Kerberos Client Registry Keys on Local Domain Controller
$kdcRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
$kerbRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

if (-not (Test-Path -Path $kdcRegPath)) {
    New-Item -Path $kdcRegPath -Force | Out-Null
}
# Enable KDC support for claims, compound authentication, and armoring (1 = Supported)
Set-ItemProperty -Path $kdcRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $kdcRegPath -Name "CbacAndArmorLevel" -Value 1 -Type DWord -Force
Write-Host "[+] Local KDC registry configured for claims and Kerberos armoring." -ForegroundColor Green

if (-not (Test-Path -Path $kerbRegPath)) {
    New-Item -Path $kerbRegPath -Force | Out-Null
}
Set-ItemProperty -Path $kerbRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord -Force
Write-Host "[+] Local Kerberos client registry configured for claims and armoring." -ForegroundColor Green

# 3. Enable Operational Event Log Channel on Domain Controller
try {
    $logChannel = "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational"
    wevtutil sl $logChannel /e:true 2>$null
    Write-Host "[+] Enabled operational log channel: $($logChannel)" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not configure operational log channel via wevtutil: $($_.Exception.Message)" -ForegroundColor Yellow
}

$enforceMode = $Enforce.IsPresent
$modeDescription = if ($enforceMode) { "Enforced" } else { "Audit Mode (Staging)" }
Write-Host "[*] Configuring Authentication Silo and Policy in mode: $($modeDescription)" -ForegroundColor Cyan

# 4. Construct Device Claims SDDL Condition
# Limits user authentication exclusively to devices belonging to the specified Silo
$deviceConditionSddl = "O:SYG:SYD:(XA;;CR;;;WD;(@Device.ad:silo == `"$SiloName`"))"

# 5. Create or Update the Authentication Policy
$existPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$PolicyName'" -ErrorAction SilentlyContinue

if (-not $existPolicy) {
    New-ADAuthenticationPolicy -Name $PolicyName `
        -Description "Authentication Policy for Tier 0 Isolation" `
        -UserTGTLifetimeMins $UserTGTLifetimeMins `
        -UserAllowedToAuthenticateFrom $deviceConditionSddl `
        -Enforce $enforceMode `
        -ProtectedFromAccidentalDeletion $true `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy '$PolicyName' created (Enforce: $($enforceMode), TGT Lifetime: $($UserTGTLifetimeMins)m)." -ForegroundColor Green
} else {
    Set-ADAuthenticationPolicy -Identity $PolicyName `
        -UserTGTLifetimeMins $UserTGTLifetimeMins `
        -UserAllowedToAuthenticateFrom $deviceConditionSddl `
        -Enforce $enforceMode `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy '$PolicyName' updated (Enforce: $($enforceMode), TGT Lifetime: $($UserTGTLifetimeMins)m)." -ForegroundColor Green
}

# 6. Create or Update the Authentication Policy Silo
$existSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$SiloName'" -ErrorAction SilentlyContinue

if (-not $existSilo) {
    New-ADAuthenticationPolicySilo -Name $SiloName `
        -Description "Authentication Policy Silo for Tier 0 Containment" `
        -UserAuthenticationPolicy $PolicyName `
        -ComputerAuthenticationPolicy $PolicyName `
        -ServiceAuthenticationPolicy $PolicyName `
        -Enforce $enforceMode `
        -ProtectedFromAccidentalDeletion $true `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy Silo '$SiloName' created (Enforce: $($enforceMode))." -ForegroundColor Green
} else {
    Set-ADAuthenticationPolicySilo -Identity $SiloName `
        -UserAuthenticationPolicy $PolicyName `
        -ComputerAuthenticationPolicy $PolicyName `
        -ServiceAuthenticationPolicy $PolicyName `
        -Enforce $enforceMode `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy Silo '$SiloName' updated (Enforce: $($enforceMode))." -ForegroundColor Green
}

# 7. Grant Silo Access and Enroll Domain Controllers (Mandatory for T0 Silo)
Write-Host "[*] Enrolling Domain Controllers into silo '$SiloName'..." -ForegroundColor White
$domainControllers = Get-ADDomainController -Filter "IsReadOnly -eq `$false"
foreach ($dc in $domainControllers) {
    $dcDn = $dc.ComputerObjectDN
    Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $dcDn -ErrorAction SilentlyContinue
    Set-ADAccountAuthenticationPolicySilo -Identity $dcDn -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
    Write-Host "    - Enrolled DC: $($dc.HostName)" -ForegroundColor Gray
}

# 8. Grant Silo Access and Enroll Tier 0 Admin Users
$userGroup = Get-ADGroup -Filter "Name -eq '$UserGroupName'" -ErrorAction SilentlyContinue
if ($userGroup) {
    Write-Host "[*] Enrolling members of user group '$UserGroupName'..." -ForegroundColor White
    $adminUsers = Get-ADGroupMember -Identity $userGroup -Recursive | Where-Object { $_.objectClass -eq "user" }
    foreach ($user in $adminUsers) {
        Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $user.distinguishedName -ErrorAction SilentlyContinue
        Set-ADAccountAuthenticationPolicySilo -Identity $user.distinguishedName -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
        Write-Host "    - Enrolled User: $($user.SamAccountName)" -ForegroundColor Gray
    }
} else {
    Write-Host "[-] User group '$UserGroupName' not found in Active Directory. Skipping user enrollment." -ForegroundColor Yellow
}

# 9. Grant Silo Access and Enroll Tier 0 PAW Computers
$compGroup = Get-ADGroup -Filter "Name -eq '$ComputerGroupName'" -ErrorAction SilentlyContinue
if ($compGroup) {
    Write-Host "[*] Enrolling members of computer group '$ComputerGroupName'..." -ForegroundColor White
    $pawComputers = Get-ADGroupMember -Identity $compGroup -Recursive | Where-Object { $_.objectClass -eq "computer" }
    foreach ($comp in $pawComputers) {
        Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $comp.distinguishedName -ErrorAction SilentlyContinue
        Set-ADAccountAuthenticationPolicySilo -Identity $comp.distinguishedName -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
        Write-Host "    - Enrolled Computer: $($comp.SamAccountName)" -ForegroundColor Gray
    }
} else {
    Write-Host "[-] Computer group '$ComputerGroupName' not found in Active Directory. Skipping computer enrollment." -ForegroundColor Yellow
}

# 10. Audit Protected Users Group Membership for Silo Users
Write-Host "[*] Auditing Protected Users membership for Tier 0 silo accounts..." -ForegroundColor White
$protectedUsersGroup = Get-ADGroup -Identity "Protected Users" -ErrorAction SilentlyContinue
if ($protectedUsersGroup) {
    $siloMembers = Get-ADAuthenticationPolicySilo -Identity $SiloName -Properties Members
    $unprotectedCount = 0
    foreach ($memberDn in $siloMembers.Members) {
        $accountObj = Get-ADObject -Identity $memberDn -Properties objectClass, sAMAccountName -ErrorAction SilentlyContinue
        if ($accountObj -and $accountObj.objectClass -eq "user") {
            $isProtected = Get-ADGroupMember -Identity "Protected Users" -Recursive | Where-Object { $_.distinguishedName -eq $memberDn }
            if (-not $isProtected) {
                Write-Host "[!] WARNING: Silo user '$($accountObj.sAMAccountName)' is NOT in Protected Users group! Vulnerable to NTLM bypass." -ForegroundColor Yellow
                $unprotectedCount++
            }
        }
    }
    if ($unprotectedCount -eq 0) {
        Write-Host "[+] All enrolled silo users are members of the Protected Users group." -ForegroundColor Green
    }
}

Write-Host "[+] Authentication Silo membership initialized." -ForegroundColor Green
```

*To audit Authentication Silos, KDC armoring configuration, enforcement states, and Protected Users group membership:*

[Download Script: Get-AuthSiloAuditStatus.ps1](audit_scripts/Get-AuthSiloAuditStatus.ps1)

```powershell
# Get-AuthSiloAuditStatus.ps1
# Description: Queries the active Authentication Silos, verifies KDC claims support, checks enforcement state, and audits Protected Users membership.
# Target Engine: Windows PowerShell 5.1

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Write-Host "--- Auditing Authentication Silos ---" -ForegroundColor Cyan

$isCompliant = $true

# 1. Audit KDC and Kerberos Client Registry Settings for Claims and Armoring
$kdcRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
$kerbRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

$kdcArmored = $false
if (Test-Path -Path $kdcRegPath) {
    $kdcEnable = (Get-ItemProperty -Path $kdcRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue).EnableCbacAndArmor
    $kdcLevel = (Get-ItemProperty -Path $kdcRegPath -Name "CbacAndArmorLevel" -ErrorAction SilentlyContinue).CbacAndArmorLevel
    if ($kdcEnable -eq 1 -and ($kdcLevel -ge 1)) {
        $kdcArmored = $true
        Write-Host "[+] Status: Compliant. KDC support for claims and Kerberos armoring is enabled." -ForegroundColor Green
    }
}

if (-not $kdcArmored) {
    Write-Host "VULNERABLE: KDC support for claims, compound authentication, and Kerberos armoring is NOT enabled in registry ($kdcRegPath)." -ForegroundColor Red
    $isCompliant = $false
}

$kerbArmored = $false
if (Test-Path -Path $kerbRegPath) {
    $kerbEnable = (Get-ItemProperty -Path $kerbRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue).EnableCbacAndArmor
    if ($kerbEnable -eq 1) {
        $kerbArmored = $true
        Write-Host "[+] Status: Compliant. Kerberos client support for claims and armoring is enabled." -ForegroundColor Green
    }
}

if (-not $kerbArmored) {
    Write-Host "VULNERABLE: Kerberos client support for claims and armoring is NOT enabled in registry ($kerbRegPath)." -ForegroundColor Red
    $isCompliant = $false
}

# 2. Audit Operational Event Log Channel
try {
    $logChannel = "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational"
    $logConfig = Get-WinEvent -ListLog $logChannel -ErrorAction Stop
    if ($logConfig.IsEnabled) {
        Write-Host "[+] Status: Compliant. Operational authentication failure event log channel is enabled." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Operational authentication failure event log channel is disabled: $($logChannel)" -ForegroundColor Red
        $isCompliant = $false
    }
} catch {
    Write-Host "[-] Operational log channel check skipped or unavailable on this node." -ForegroundColor Yellow
}

# 3. Audit Active Directory Authentication Policy Silos
try {
    $silos = Get-ADAuthenticationPolicySilo -Filter * -Properties * -ErrorAction Stop
    if (-not $silos) {
        Write-Host "VULNERABLE: No Active Directory Authentication Policy Silos configured in this domain." -ForegroundColor Red
        $isCompliant = $false
    } else {
        foreach ($silo in $silos) {
            Write-Host "[*] Silo Name: $($silo.Name)" -ForegroundColor Cyan
            Write-Host "    - Description: $($silo.Description)" -ForegroundColor White
            Write-Host "    - Enforced: $($silo.Enforce)" -ForegroundColor White
            Write-Host "    - User Policy: $($silo.UserAuthenticationPolicy)" -ForegroundColor White
            Write-Host "    - Computer Policy: $($silo.ComputerAuthenticationPolicy)" -ForegroundColor White

            if (-not $silo.Enforce) {
                Write-Host "    [!] Silo '$($silo.Name)' is in AUDIT mode (Enforce = False). Verify staging logs before enforcement." -ForegroundColor Yellow
            }

            # Verify associated User Authentication Policy
            if ($silo.UserAuthenticationPolicy) {
                $userPolicy = Get-ADAuthenticationPolicy -Identity $silo.UserAuthenticationPolicy -Properties * -ErrorAction SilentlyContinue
                if ($userPolicy) {
                    Write-Host "    - User TGT Lifetime: $($userPolicy.UserTGTLifetimeMins) minutes" -ForegroundColor White
                    Write-Host "    - Policy Enforced: $($userPolicy.Enforce)" -ForegroundColor White
                    if ($userPolicy.UserTGTLifetimeMins -gt 240) {
                        Write-Host "    [!] Policy TGT lifetime exceeds 240 minutes ($($userPolicy.UserTGTLifetimeMins)m)." -ForegroundColor Yellow
                    }
                }
            }

            # Check Silo Members: DCs must be enrolled in T0 Silo
            if ($silo.Name -like "*T0*" -or $silo.Name -like "*Tier0*") {
                $dcs = Get-ADDomainController -Filter "IsReadOnly -eq `$false" -ErrorAction SilentlyContinue
                $missingDcs = 0
                foreach ($dc in $dcs) {
                    $assignedSilo = (Get-ADAccountAuthenticationPolicySilo -Identity $dc.ComputerObjectDN -ErrorAction SilentlyContinue).AuthenticationPolicySilo
                    if (-not $assignedSilo -or $assignedSilo -ne $silo.DistinguishedName) {
                        $missingDcs++
                    }
                }
                if ($missingDcs -gt 0) {
                    Write-Host "    VULNERABLE: $($missingDcs) writable Domain Controller(s) are NOT assigned to Tier 0 Silo '$($silo.Name)'." -ForegroundColor Red
                    $isCompliant = $false
                } else {
                    Write-Host "    [+] All writable Domain Controllers are assigned to Tier 0 Silo." -ForegroundColor Green
                }
            }

            # Check Silo Members: User accounts must be members of Protected Users group
            $members = $silo.Members
            $unprotectedUsers = 0
            if ($members) {
                foreach ($memberDn in $members) {
                    $memberObj = Get-ADObject -Identity $memberDn -Properties objectClass, sAMAccountName -ErrorAction SilentlyContinue
                    if ($memberObj -and $memberObj.objectClass -eq "user") {
                        $isProtected = Get-ADGroupMember -Identity "Protected Users" -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.distinguishedName -eq $memberDn }
                        if (-not $isProtected) {
                            $unprotectedUsers++
                            Write-Host "    VULNERABLE: Silo user '$($memberObj.sAMAccountName)' is NOT in Protected Users group (NTLM bypass risk)!" -ForegroundColor Red
                        }
                    }
                }
            }
            if ($unprotectedUsers -gt 0) {
                $isCompliant = $false
            }
        }
    }
} catch {
    Write-Host "[-] Could not query Active Directory Authentication Policy Silos: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. Final Compliance Verdict
if ($isCompliant) {
    Write-Host "Audit Result: SECURE (Authentication Silos and Policies configured and compliant)" -ForegroundColor Green
} else {
    Write-Host "Audit Result: VULNERABLE (Authentication Silos and Policies missing or non-compliant)" -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**:
  * Recommendation R8: Activer l'armement Kerberos et l'authentification composée
  * Recommendation R14: Utiliser le groupe Protected Users
  * Recommendation R64: Mettre en œuvre des silos et des politiques d'authentification pour le Tier 0
  * Recommendation R80: Définir des politiques d'authentification pour les groupes d'administration
  * Annexe C: Mise en œuvre d'un silo d'authentification
* **ANSSI Remediation of Active Directory Tier 0 Guide**:
  * Section 10.g: Cloisonnement cryptographique et silos d'authentification (Page 40)
  * Section 11: Mise en œuvre des politiques et silos d'authentification (Page 49)
* **Microsoft Security Guidance**:
  * Authentication Policies and Authentication Policy Silos Overview
  * How to Configure Protected Accounts
  * RFC 6113: Flexible Authentication Secure Tunneling (FAST)
* **MITRE ATT&CK**:
  * T1078: Valid Accounts (Domain Accounts)
  * T1550.002: Use Alternate Authentication Material - Pass the Hash
  * T1550.003: Use Alternate Authentication Material - Pass the Ticket
  * T1558: Steal or Forge Kerberos Tickets
