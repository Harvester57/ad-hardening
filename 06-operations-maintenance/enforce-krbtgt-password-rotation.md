# [REQ-OPS-001] Enforce KRBTGT Password Rotation

## Target Scope
* **Applicable Systems**: Domain Controllers (Primary Domain Controller / PDC Emulator, replica Domain Controllers)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025
* **Directory Scope**: Forest Root Domain, Child Domains, and Read-Only Domain Controllers (RODCs)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Object Management (krbtgt account object in the Users container: `CN=krbtgt,CN=Users,DC=[Domain],DC=[tld]`)
  * **Primary KRBTGT Object**: `CN=krbtgt,CN=Users,DC=[Domain],DC=[tld]`
  * **RODC KRBTGT Objects**: `CN=krbtgt_[RODC-Identifier],CN=Users,DC=[Domain],DC=[tld]`
  * **Key Monitored Attributes**: `pwdLastSet`, `msDS-KeyVersionNumber` (`kvno`), `msDS-SupportedEncryptionTypes`, `whenChanged`, `userAccountControl`

> [!WARNING]
> The `krbtgt` account password must be rotated periodically using a two-step rotation process to limit the lifespan of potentially compromised Ticket Granting Tickets (TGTs).
> * **Standard Frequency (DoD STIG)**: Reset the password at least every 180 days (semi-annually) in accordance with DoD STIG requirements (V-205877, V-225006, V-254427).
> * **High-Security Frequency (ANSSI)**: High-security baselines (such as the ANSSI Active Directory hardening guide, recommendation R23) recommend rotating the password every 40 to 90 days.
> * **Incident Response / Ad-Hoc Rotation**: Perform an immediate two-step rotation in the event of a suspected Active Directory compromise, DCSync activity, NTDS.dit exfiltration, Golden/Diamond ticket detection, or following the departure of administrative staff with Tier 0 access.

---

## Rationale

The `krbtgt` account is a built-in local service account that serves as the Key Distribution Center (KDC) service account in Active Directory. The long-term secret cryptographic keys derived from the `krbtgt` account password are used by the KDC to sign and encrypt all Kerberos Ticket Granting Tickets (TGTs) issued within the domain, as well as to compute the Privilege Attribute Certificate (PAC) signatures that vouch for user identity, security identifiers (SIDs), and group memberships.

### 1. Kerberos Ticket Forgery Attack Vectors

If an adversary compromises Active Directory credentials with directory replication privileges (DCSync via `DS-Replication-Get-Changes-All`), dumps the `NTDS.dit` database (e.g., via Volume Shadow Copy or raw disk extraction), or compromises Domain Admin privileges, they can harvest the `krbtgt` password hashes and keys. Possessing these keys enables several devastating persistence and privilege escalation attacks:

* **Golden Ticket Attacks (MITRE ATT&CK T1558.001)**:
  An attacker uses the `krbtgt` NTLM hash or AES keys to construct forged Kerberos TGTs entirely offline without interacting with a Domain Controller. The attacker can inject arbitrary user identities (including non-existent users), assign the well-known RID 500 (`Administrator`), embed membership in privileged groups (e.g., `Domain Admins`, `Enterprise Admins`, `Schema Admins`), and specify arbitrarily long validity periods (often 10 years). When presented to any service in the domain, the KDC accepts the forged TGT because it successfully decrypts with the `krbtgt` key, issuing service tickets (`TGS`) without re-validating the user's account state or password in Active Directory.
* **Diamond Ticket Attacks**:
  In a Diamond Ticket attack, an attacker requests a legitimate TGT from the KDC via standard `AS-REQ` / `AS-REP` exchange, decrypts the issued ticket using the stolen `krbtgt` key, modifies the PAC to add high-privilege group SIDs, recalculates the PAC signatures using the `krbtgt` key, and re-encrypts the TGT. This bypasses behavioral detection systems that look for anomalous TGT issuance lacking prior Kerberos authentication traffic.
* **Sapphire Ticket Attacks**:
  In a Sapphire Ticket attack, an attacker leverages Kerberos S4U2self (Service for User to Self) to obtain a legitimate, cryptographically authentic PAC for an administrative account, and transplants that authentic PAC into a forged ticket signed with the `krbtgt` key, making the forged authorization payload indistinguishable from legitimate directory traffic.
* **PAC Signature Validation & CVE-2022-37967**:
  Active Directory security updates enforce strong HMAC-SHA1 AES algorithms for PAC signatures (`KERB_CHECKSUM_HMAC_SHA1_96_AES128` / `KERB_CHECKSUM_HMAC_SHA1_96_AES256`). Because PAC signatures are generated using the KDC's `krbtgt` keys, rotating `krbtgt` invalidates all PAC checksums generated under previous compromised keys.

### 2. The Two-Password History Architecture and `kvno`

Active Directory maintains the current password and the immediately previous password for the `krbtgt` account in its database:
* **Current Key (History Index 0)**: Used by the KDC to encrypt and sign newly issued TGTs.
* **Previous Key (History Index 1)**: Retained by the KDC to allow existing, legitimately issued TGTs to be decrypted and validated during renewal or service ticket requests, avoiding immediate operational disruption.

Each password update increments the Key Version Number (`msDS-KeyVersionNumber` or `kvno`) of the `krbtgt` account:

```
====================================================================================================
                        TWO-STEP KRBTGT ROTATION LIFECYCLE
====================================================================================================

 INITIAL STATE (Compromised or Expired Key):
 +-------------------------+-------------------------+
 | Current Key: kvno = 10  | Previous Key: kvno = 9  |  <-- Attacker holds kvno = 10 hash
 +-------------------------+-------------------------+      (Golden Tickets active)

 STEP 1: First Password Reset
 +-------------------------+-------------------------+
 | Current Key: kvno = 11  | Previous Key: kvno = 10 |  <-- New tickets issued with kvno = 11.
 +-------------------------+-------------------------+      Old valid tickets & Golden Tickets
                                                            (kvno = 10) still decrypt via index 1.

 COOLDOWN WINDOW: Wait >= 10 Hours (Recommended: 24 Hours)
 - Active Directory replication converges across all Domain Controllers.
 - Legitimate user/computer TGTs naturally expire or renew, adopting kvno = 11.

 STEP 2: Second Password Reset
 +-------------------------+-------------------------+
 | Current Key: kvno = 12  | Previous Key: kvno = 11 |  <-- kvno = 10 is PURGED from AD history.
 +-------------------------+-------------------------+      ALL Golden/Diamond tickets signed with
                                                            kvno <= 10 fail decryption and are rejected!
====================================================================================================
```

* **First Reset (Step 1)**: Increments the `kvno` to `N+1`. The compromised key shifts to history index 1. Newly issued TGTs use `kvno = N+1`. Existing legitimate user sessions continue uninterrupted because the KDC can still decrypt tickets signed with `kvno = N`.
* **Cooldown Period**: A mandatory waiting period allowing Active Directory replication to converge across all Domain Controllers and existing legitimate Kerberos tickets (default lifetime of 10 hours) to expire or renew using `kvno = N+1`.
* **Second Reset (Step 2)**: Increments the `kvno` to `N+2`. The key from Step 1 (`kvno = N+1`) shifts to history index 1, and the compromised key (`kvno = N`) is **permanently purged** from the Active Directory database. At this point, any Golden Ticket forged with `kvno = N` is rejected with `KRB_AP_ERR_MODIFIED` (`0x29`) or `KDC_ERR_TGT_REVOKED` (`0x17`).

### 3. Kerberos Policy Timers and Cooldown Window

The cooldown window between the first and second reset is governed by the domain Kerberos Policy configured in the Default Domain Policy:
1. **Maximum lifetime for user ticket (`MaxTicketAge`)**: Default is **10 hours** (600 minutes). Legitimate user TGTs remain valid for this duration.
2. **Maximum lifetime for user ticket renewal (`MaxRenewAge`)**: Default is **7 days**. When a client renews an existing TGT, the KDC issues a renewed ticket signed with the current key (`kvno = N+1`).
3. **Maximum lifetime for service ticket (`MaxServiceAge`)**: Default is **10 hours** (600 minutes).
4. **Maximum tolerance for computer clock synchronization (`MaxClockSkew`)**: Default is **5 minutes**.

Because legitimate clients automatically renew their TGTs before `MaxTicketAge` elapses, waiting at least 10 hours (24 hours recommended in production to account for replication latency and multi-site links) guarantees that all legitimate sessions have migrated to the new key before the second reset purges the previous key.

### 4. Read-Only Domain Controllers (RODCs) and `krbtgt_XXXXX`

Read-Only Domain Controllers (RODCs) introduce a distinct architectural separation:
* Each RODC possesses a dedicated `krbtgt` account named `krbtgt_[RODC-Identifier]` (e.g., `krbtgt_12345`).
* RODCs do **not** store the main domain `krbtgt` account key. Instead, the RODC signs TGTs using its own specific `krbtgt_[RODC-Identifier]` key.
* The domain-wide `krbtgt` password rotation does **not** rotate RODC `krbtgt` keys.
* If an RODC is physically stolen or its database extracted, administrators must specifically reset that RODC's dedicated `krbtgt_[RODC-Identifier]` account and invalidate all user accounts whose credentials were cached on that RODC according to its Password Replication Policy (PRP).

### 5. Multi-Domain Forests and Inter-Realm Trusts

In a multi-domain Active Directory forest, each domain maintains its own independent `krbtgt` account. Cross-domain authentication within a forest utilizes inter-realm referral TGTs signed with inter-realm trust keys stored in Trusted Domain Objects (TDOs), rather than the root domain's `krbtgt` key. However, if the forest root domain `krbtgt` is compromised, an attacker can forge inter-realm referral tickets that grant Enterprise Admin access across all child domains. Therefore, in a forest recovery scenario, `krbtgt` accounts across all domains in the forest must be systematically rotated.

### 6. Security Event Auditing

Monitor the following Windows Security Event Log IDs on all Domain Controllers during and following `krbtgt` rotation:
* **Event ID 4723**: An attempt was made to change an account's password (target: `krbtgt`).
* **Event ID 4724**: An attempt was made to reset an account's password (target: `krbtgt`).
* **Event ID 4738**: A user account was changed (shows modifications to `krbtgt` attributes such as `pwdLastSet`).
* **Event ID 4768**: A Kerberos authentication ticket (TGT) was requested.
* **Event ID 4769**: A Kerberos service ticket was requested (look for failure code `0x1F` or `0x29` indicating outdated or forged keys).
* **Event ID 4771**: Kerberos pre-authentication failed (failure code `0x18` indicating bad password, or `0x17` indicating TGT revoked).

---

## Legacy Impact & Compatibility

* **Authentication Outage Hazard from Premature Double Reset**: Resetting the `krbtgt` password twice in rapid succession (without waiting for the Kerberos ticket lifetime and replication to complete) purges active tickets from both history slots. This immediately invalidates **all** active TGTs across the enterprise, causing massive, domain-wide authentication failures for all users, computer logons, background services, scheduled tasks, and Kerberos-authenticated applications.
* **Operational Wait Time**: A minimum of 10 hours (24 hours is strongly recommended for production environments with multi-site Active Directory replication) must be observed between the first and second reset.
* **Trust Relationships**: Cross-forest and external trusts use independent shared trust keys and are not invalidated by domain `krbtgt` rotation. However, cross-domain referral tickets in flight during an emergency double-reset may require renewal.
* **Group Managed Service Accounts (gMSA)**: gMSAs automatically renew their Kerberos tickets based on standard ticket lifespans. As long as the cooldown window is observed, gMSA services will experience zero interruption.
* **Direct Azure AD / Entra ID Connect Impact**: Pass-through authentication and password hash synchronization are unaffected by `krbtgt` rotation, but seamless SSO (Kerberos-based) relying on the `AZUREADSSOACC` computer account relies on Kerberos ticket renewal within standard lifetimes.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Baseline & Staged Administrative Procedure

Kerberos ticket lifetimes are governed via Group Policy Objects, while the password rotation itself is an operational database procedure executed against Active Directory objects.

#### 1. Verify and Enforce Domain Kerberos Policy via GPO

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the **Default Domain Policy** (or a dedicated Tier 0 Domain Controller Policy linked at the domain root).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy`
4. Verify and enforce standard Kerberos parameters:
   * **Enforce user logon restrictions**: `Enabled`
   * **Maximum lifetime for service ticket**: `600` minutes (10 hours)
   * **Maximum lifetime for user ticket**: `10` hours
   * **Maximum lifetime for user ticket renewal**: `7` days
   * **Maximum tolerance for computer clock synchronization**: `5` minutes

#### 2. Staged Administrative Procedure for KRBTGT Rotation

To execute the staged rotation using Active Directory administrative tools:

##### Phase 1: Pre-Rotation Assessment
1. Identify the Primary Domain Controller (PDC) Emulator for the domain:
   ```cmd
   netdom query fsmo
   ```
2. Verify that Active Directory replication is completely healthy across all Domain Controllers:
   ```cmd
   repadmin /replsummary
   repadmin /showrepl * /csv
   ```
3. Audit the existing `krbtgt` password age and `kvno` (using the audit script below).

##### Phase 2: First Password Reset (Step 1)
1. Log on to the **PDC Emulator** with Domain Admin or Enterprise Admin credentials.
2. Open **Active Directory Users and Computers** (`dsa.msc`), ensure **View -> Advanced Features** is enabled.
3. Navigate to the **Users** container, right-click **krbtgt**, and select **Reset Password**.
4. Enter a strong, cryptographically complex random password (minimum 128 characters) and confirm it. Click **OK**.
5. Trigger replication across all Domain Controllers:
   ```cmd
   repadmin /syncall /AdeP
   ```

##### Phase 3: Cooldown and Ticket Expiration Window
1. Wait a minimum of **10 to 24 hours**.
2. Monitor Domain Controller Security Event Logs for Kerberos ticket renewal events (Event ID 4768) and verify replication convergence.

##### Phase 4: Second Password Reset (Step 2)
1. On the PDC Emulator, repeat the password reset procedure on the **krbtgt** account with a new, distinct 128-character password.
2. Trigger replication across all Domain Controllers:
   ```cmd
   repadmin /syncall /AdeP
   ```

##### Phase 5: Post-Rotation Verification
1. Run the audit script below to verify that all Domain Controllers report the updated `PasswordLastSet` and matching `kvno`.

---

### Option B: PowerShell Operational Automation (Remediation / Audit)

Use the following enterprise-grade PowerShell scripts to programmatically manage and audit the KRBTGT password rotation lifecycle.

[Download Script: Reset-KrbtgtPassword.ps1](implementation_scripts/Reset-KrbtgtPassword.ps1)

```powershell
# Reset-KrbtgtPassword.ps1
# Description: Resets the KRBTGT account password on the PDC Emulator with a cryptographically secure 128-character password, enforces cooldown safety, and triggers AD replication.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [int]$MinCooldownHours = 10,

    [Parameter(Mandatory = $false)]
    [string]$Server
)

Write-Host "--- Applying Hardening Requirement: KRBTGT Password Rotation ---" -ForegroundColor Cyan

# 1. Verify Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required to execute this script."
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

# 2. Discover target Domain Controller (PDC Emulator)
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $targetServer = $Server
    if (-not $targetServer) {
        $targetServer = $domain.PDCEmulator
    }
    Write-Host "[*] Target Domain: $($domain.DNSRoot)" -ForegroundColor Gray
    Write-Host "[*] Authoritative PDC Emulator: $targetServer" -ForegroundColor Gray
} catch {
    Write-Error "Failed to locate domain or PDC Emulator: $($_.Exception.Message)"
    return
}

# 3. Retrieve authoritative KRBTGT object
try {
    $krbtgt = Get-ADUser -Identity "krbtgt" -Server $targetServer -Properties PasswordLastSet, Enabled, "msDS-KeyVersionNumber", userAccountControl -ErrorAction Stop
    if (-not $krbtgt) {
        Write-Error "KRBTGT account not found on $targetServer."
        return
    }
} catch {
    Write-Error "Failed to retrieve KRBTGT account from $($targetServer): $($_.Exception.Message)"
    return
}

$lastSet = $krbtgt.PasswordLastSet
$currentKvno = $krbtgt."msDS-KeyVersionNumber"

Write-Host "[*] Current KRBTGT Password Last Set: $lastSet" -ForegroundColor Gray
Write-Host "[*] Current Key Version Number (kvno): $currentKvno" -ForegroundColor Gray

# 4. Enforce Cooldown Safety Check
if ($null -ne $lastSet) {
    $elapsedHours = (New-TimeSpan -Start $lastSet -End (Get-Date)).TotalHours
    if ($elapsedHours -lt $MinCooldownHours -and -not $Force) {
        $roundedHours = [math]::Round($elapsedHours, 1)
        Write-Warning "SAFETY INTERLOCK ENGAGED: The KRBTGT password was last set only $roundedHours hours ago."
        Write-Warning "Resetting KRBTGT again before the Kerberos ticket lifetime ($MinCooldownHours hours) has elapsed"
        Write-Warning "will purge the previous key from history and invalidate ALL active domain TGTs,"
        Write-Warning "causing enterprise-wide authentication failure for all users and services."
        Write-Warning "To override this interlock (e.g., during active incident containment), specify -Force."
        return
    }
}

# 5. Generate Cryptographically Secure 128-Character Password
$length = 128
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$bytes = New-Object byte[] $length
$rng.GetBytes($bytes)

$securePassword = New-Object System.Security.SecureString
for ($i = 0; $i -lt $length; $i++) {
    $char = $chars[$bytes[$i] % $chars.Length]
    $securePassword.AppendChar($char)
}
$securePassword.MakeReadOnly()
$rng.Dispose()

# 6. Execute Password Reset via ShouldProcess
$confirmTarget = "KRBTGT account on $targetServer (Domain: $($domain.DNSRoot))"
if ($PSCmdlet.ShouldProcess($confirmTarget, "Reset KRBTGT account password and increment kvno")) {
    try {
        Set-ADAccountPassword -Identity $krbtgt -Server $targetServer -NewPassword $securePassword -Reset -ErrorAction Stop
        Write-Host "[+] KRBTGT password successfully reset on PDC Emulator ($targetServer)." -ForegroundColor Green

        # Re-query to verify kvno increment
        Start-Sleep -Seconds 2
        $updatedKrbtgt = Get-ADUser -Identity "krbtgt" -Server $targetServer -Properties PasswordLastSet, "msDS-KeyVersionNumber" -ErrorAction Stop
        Write-Host "[+] New Password Last Set: $($updatedKrbtgt.PasswordLastSet)" -ForegroundColor Green
        Write-Host "[+] New Key Version Number (kvno): $($updatedKrbtgt.'msDS-KeyVersionNumber')" -ForegroundColor Green

        # 7. Dispatch Active Directory Replication
        Write-Host "[*] Triggering Active Directory replication synchronization..." -ForegroundColor Cyan
        $repadmin = Get-Command -Name "repadmin.exe" -ErrorAction SilentlyContinue
        if ($repadmin) {
            & repadmin.exe /syncall /AdeP | Out-Null
            Write-Host "[+] Active Directory replication triggered across all domain partitions." -ForegroundColor Green
        } else {
            try {
                Sync-ADObject -Identity $krbtgt.DistinguishedName -Server $targetServer -ErrorAction SilentlyContinue
                Write-Host "[+] Sync-ADObject invoked for KRBTGT account." -ForegroundColor Green
            } catch {
                Write-Warning "Could not trigger replication automatically. Ensure replication runs across all domain controllers."
            }
        }

        Write-Host ""
        Write-Host "=========================================================================" -ForegroundColor Yellow
        Write-Host "[IMPORTANT] Two-Step KRBTGT Password Rotation Protocol:" -ForegroundColor Yellow
        Write-Host " 1. This reset constitutes Step 1 of the rotation cycle." -ForegroundColor Yellow
        Write-Host " 2. Active Directory retains the previous key in history (index 1) so" -ForegroundColor Yellow
        Write-Host "    existing valid Kerberos tickets continue to function until expiration." -ForegroundColor Yellow
        Write-Host " 3. You MUST WAIT at least $MinCooldownHours to 24 hours for all active tickets" -ForegroundColor Yellow
        Write-Host "    to renew and for replication to converge across all domain controllers." -ForegroundColor Yellow
        Write-Host " 4. After the cooldown period, run this script again to perform Step 2," -ForegroundColor Yellow
        Write-Host "    which purges the pre-rotation key and completely invalidates any" -ForegroundColor Yellow
        Write-Host "    historical Golden, Diamond, or forged Kerberos tickets." -ForegroundColor Yellow
        Write-Host "=========================================================================" -ForegroundColor Yellow
    } catch {
        Write-Error "Failed to reset KRBTGT password: $($_.Exception.Message)"
    }
}
```

*To audit the password rotation status and replication convergence of the KRBTGT account:*

[Download Script: Get-KrbtgtRotationStatus.ps1](audit_scripts/Get-KrbtgtRotationStatus.ps1)

```powershell
# Get-KrbtgtRotationStatus.ps1
# Description: Audits KRBTGT password age, kvno, replication convergence across all Domain Controllers, and RODC accounts.
# Target Engine: Windows PowerShell 5.1

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "--- Auditing KRBTGT Password Rotation Status ---" -ForegroundColor Cyan

# 1. Discover Domain and Authoritative PDC Emulator
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $pdc = $domain.PDCEmulator
    Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Gray
    Write-Host "[*] Authoritative PDC Emulator: $pdc" -ForegroundColor Gray
} catch {
    Write-Error "Failed to query domain or PDC Emulator: $($_.Exception.Message)"
    return
}

# 2. Retrieve Kerberos Policy MaxTicketAge
$maxTicketAgeHours = 10
try {
    $kerbPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($kerbPolicy -and $kerbPolicy.MaxTicketAge) {
        $maxTicketAgeHours = [math]::Round($kerbPolicy.MaxTicketAge.TotalHours, 1)
    }
} catch {
    $maxTicketAgeHours = 10
}
Write-Host "[*] Configured Kerberos MaxTicketAge: $maxTicketAgeHours hours" -ForegroundColor Gray

# 3. Query Primary KRBTGT Object on PDC
$krbtgt = Get-ADUser -Identity "krbtgt" -Server $pdc -Properties PasswordLastSet, PasswordExpired, Enabled, "msDS-KeyVersionNumber", "msDS-SupportedEncryptionTypes" -ErrorAction SilentlyContinue

if (-not $krbtgt) {
    Write-Error "KRBTGT account not found in Active Directory."
    return
}

$passwordLastSet = $krbtgt.PasswordLastSet
$kvno = $krbtgt."msDS-KeyVersionNumber"
$encTypes = $krbtgt."msDS-SupportedEncryptionTypes"

Write-Host "    - Account Name: $($krbtgt.Name)" -ForegroundColor White
Write-Host "    - Enabled: $($krbtgt.Enabled)" -ForegroundColor White
Write-Host "    - Key Version Number (kvno): $kvno" -ForegroundColor White
Write-Host "    - Supported Encryption Types Bitmask: $encTypes" -ForegroundColor White

if ($null -ne $passwordLastSet) {
    $ageDays = (New-TimeSpan -Start $passwordLastSet -End (Get-Date)).Days
    $ageHours = (New-TimeSpan -Start $passwordLastSet -End (Get-Date)).TotalHours
    $stigThresholdDays = 180
    $anssiThresholdDays = 90

    Write-Host "    - Password Last Set: $passwordLastSet ($ageDays days ago / $([math]::Round($ageHours, 1)) hours ago)" -ForegroundColor White

    # Check if currently inside the two-step cooldown window
    if ($ageHours -lt $maxTicketAgeHours) {
        Write-Host "    - Cooldown Status: IN-PROGRESS (Step 1 executed $([math]::Round($ageHours, 1)) hours ago; wait until $maxTicketAgeHours hours have elapsed before executing Step 2)." -ForegroundColor Yellow
    }

    # Evaluate compliance thresholds
    if ($ageDays -gt $stigThresholdDays) {
        Write-Host "    - Compliance Status: FAILED - KRBTGT password has not been rotated in $ageDays days (DoD STIG threshold: $stigThresholdDays days)." -ForegroundColor Red
    } elseif ($ageDays -gt $anssiThresholdDays) {
        Write-Host "    - Compliance Status: WARNING - KRBTGT password age is $ageDays days (Exceeds ANSSI recommendation of $anssiThresholdDays days; compliant with STIG threshold of $stigThresholdDays days)." -ForegroundColor Yellow
    } else {
        Write-Host "    - Compliance Status: PASSED - KRBTGT password age is $ageDays days (Compliant with STIG and ANSSI baselines)." -ForegroundColor Green
    }
} else {
    Write-Host "    - Compliance Status: FAILED - PasswordLastSet attribute is null." -ForegroundColor Red
}

# 4. Audit Replication Consistency Across All Reachable DCs
Write-Host "`n[*] Auditing KRBTGT Replication Convergence Across Domain Controllers:" -ForegroundColor Cyan
$dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
$dcResults = @()
$replicationDiscrepancy = $false

foreach ($dc in $dcs) {
    try {
        $dcKrbtgt = Get-ADUser -Identity "krbtgt" -Server $dc.HostName -Properties PasswordLastSet, "msDS-KeyVersionNumber" -ErrorAction Stop
        $match = ($dcKrbtgt.PasswordLastSet -eq $passwordLastSet) -and ($dcKrbtgt."msDS-KeyVersionNumber" -eq $kvno)
        if (-not $match) {
            $replicationDiscrepancy = $true
        }
        $dcResults += [PSCustomObject]@{
            DomainController = $dc.HostName
            Reachable        = $true
            PasswordLastSet  = $dcKrbtgt.PasswordLastSet
            Kvno             = $dcKrbtgt."msDS-KeyVersionNumber"
            InSync           = $match
        }
    } catch {
        $dcResults += [PSCustomObject]@{
            DomainController = $dc.HostName
            Reachable        = $false
            PasswordLastSet  = $null
            Kvno             = $null
            InSync           = $false
        }
    }
}

foreach ($res in $dcResults) {
    if ($res.Reachable -and $res.InSync) {
        Write-Host "    [OK] $($res.DomainController): kvno=$($res.Kvno), LastSet=$($res.PasswordLastSet)" -ForegroundColor Green
    } elseif ($res.Reachable -and -not $res.InSync) {
        Write-Host "    [MISMATCH] $($res.DomainController): kvno=$($res.Kvno), LastSet=$($res.PasswordLastSet) (Out of sync with PDC)" -ForegroundColor Red
    } else {
        Write-Host "    [UNREACHABLE] $($res.DomainController): Unable to query" -ForegroundColor Yellow
    }
}

if ($replicationDiscrepancy) {
    Write-Host "    [!] Warning: Replication discrepancy detected across Domain Controllers." -ForegroundColor Red
}

# 5. Audit Read-Only Domain Controller (RODC) KRBTGT Accounts
Write-Host "`n[*] Auditing Read-Only Domain Controller (RODC) KRBTGT Accounts:" -ForegroundColor Cyan
$rodcAccounts = Get-ADUser -Filter "Name -like 'krbtgt_*'" -Server $pdc -Properties PasswordLastSet, "msDS-KeyVersionNumber", Enabled -ErrorAction SilentlyContinue

if ($rodcAccounts -and $rodcAccounts.Count -gt 0) {
    Write-Host "    Found $($rodcAccounts.Count) RODC KRBTGT account(s):" -ForegroundColor Gray
    foreach ($rodc in $rodcAccounts) {
        $rodcAgeDays = "N/A"
        if ($rodc.PasswordLastSet) {
            $rodcAgeDays = (New-TimeSpan -Start $rodc.PasswordLastSet -End (Get-Date)).Days
        }
        Write-Host "    - $($rodc.SamAccountName): kvno=$($rodc.'msDS-KeyVersionNumber'), LastSet=$($rodc.PasswordLastSet) ($rodcAgeDays days ago), Enabled=$($rodc.Enabled)" -ForegroundColor White
    }
} else {
    Write-Host "    No Read-Only Domain Controller (RODC) accounts detected in this domain." -ForegroundColor Gray
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R23 (Secrets renewal - Renouvellement des secrets de l'Active Directory: Rotate KRBTGT password every 40 to 90 days and following security incidents).
* **DoD STIG**:
  * Windows Server 2016 Domain Controller STIG: V-205877 (WN16-DC-000270)
  * Windows Server 2019 Domain Controller STIG: V-225006 (WN19-DC-000270)
  * Windows Server 2022 Domain Controller STIG: V-254427 (WN22-DC-000270)
  * Windows Server 2025 Domain Controller STIG: The `krbtgt` account password must be reset at least every 180 days.
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark (General Guidance on Kerberos TGT Key Lifecycle and Periodic Rotation).
* **Microsoft Security Guidance**:
  * "Securing the KRBTGT Account"
  * "Active Directory Forest Recovery - Reset the krbtgt Password"
  * RFC 4120: The Kerberos Network Authentication Service (V5)
  * RFC 3961 / RFC 3962: Encryption and Checksum Specifications for Kerberos 5
* **MITRE ATT&CK**:
  * [T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
  * [T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)
  * [T1003.006 - OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/)
