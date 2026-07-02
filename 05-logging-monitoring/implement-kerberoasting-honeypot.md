# [REQ-LOG-005] Configure Kerberoasting Honeypots and SIEM Detection Rules

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Active Directory Object Management (Account attributes: `servicePrincipalName`, `adminCount`, `LogonWorkstations`)

---

## Rationale
Kerberoasting allows an authenticated user to request a Kerberos service ticket (TGS) for any service account mapped to a Service Principal Name (SPN). Because the ticket is encrypted using the service account's password hash, the attacker can extract the encrypted ticket from memory and attempt to crack the password offline using brute-force dictionaries or GPU arrays.

To mitigate and detect this vector, two strategies must be implemented:

1. **Service Account Honeypots (Decoy Accounts)**:
   By creating a fake Active Directory user account and registering a decoy SPN on it, security teams establish a high-fidelity trap. Since this decoy account is not tied to any legitimate application or service, no standard user or system has any reason to request a Kerberos ticket for it. 
   - Set the `adminCount` attribute to `1` so the account appears in attacker search queries searching for high-privilege targets (e.g., Domain Admins).
   - Any ticket request (Event ID 4769) for the decoy SPN is a definitive indicator of a Kerberoasting attempt, providing a zero-false-positive alert with the attacker's client IP.

2. **SIEM Filtering and Correlation**:
   Standard Event ID 4769 logging generates millions of events daily. Filtering this telemetry down to anomalous behavior is necessary to catch broad Kerberoasting scans:
   - **Ticket Encryption Type**: Focus on encryption type `0x17` (RC4-HMAC-MD5) or legacy DES (`0x1`, `0x2`, `0x3`) as modern Windows environments negotiate AES (`0x11` or `0x12`) by default.
   - **Account Exclusions**: Filter out usernames ending with `$` (which represent computer accounts, trusts, or managed service accounts that feature automatically rotated, high-entropy passwords).
   - **Anomalous Patterns**: Trigger alerts when a single user account requests RC4 or DES tickets for multiple distinct SPNs within a short timeframe (e.g., less than 5 seconds).

---

## Legacy Impact & Compatibility
* **Disabled Interactive Logon**: The honeypot account is a decoy and must never be allowed to log on to any system. Enforcing a logon workstation restriction to a non-existent host (e.g., `HONEYPOT-VOID-HOST`) ensures the account cannot be actively abused for lateral movement or authentication even if the password is leaked or cracked.
* **TGS Ticket Issuance**: Active Directory KDC will still issue service tickets for a user account even when logon workstation restrictions are active, ensuring the security audit event (Event ID 4769) is generated for the SIEM to alert on.

---

## Implementation Steps

### Option A: Active Directory Users and Computers (GUI)

#### 1. Create the Decoy Account
1. Log on to a Domain Controller or administrative workstation with Domain Admin privileges.
2. Open **Active Directory Users and Computers** (`dsa.msc`).
3. Create a new User Object (e.g., named `krbtgt_honey`).
4. Set a strong, complex 120-character password.
5. In the account options:
   - Ensure **Account is enabled** is checked.
   - Check **Password never expires**.
6. Open the user properties and navigate to the **Account** tab:
   - Click **Log On To...** under Logon Workstations.
   - Select **The following computers** and enter a non-existent hostname (e.g., `HONEYPOT-VOID-HOST`).
   - Click **Add** and then **OK**.

#### 2. Configure administrative attributes
1. In Active Directory Users and Computers, select **View** -> **Advanced Features** to enable the Attribute Editor.
2. Open the properties of the decoy account and navigate to the **Attribute Editor** tab.
3. Locate the `adminCount` attribute and double-click it.
4. Set the value to `1` and click **OK**.

#### 3. Register the Decoy SPN
1. Open an elevated command prompt on the Domain Controller.
2. Register a unique fake SPN using the `setspn` tool:
   ```cmd
   setspn -s MSSQLSvc/sql-backup-prod.domain.local:1433 krbtgt_honey
   ```

---

### Option B: PowerShell & Active Directory cmdlets

Use this method to automatically deploy the honeypot configuration and audit its compliance status.

[Download Script: New-KerberoastHoneypot.ps1](implementation_scripts/New-KerberoastHoneypot.ps1)

```powershell
# New-KerberoastHoneypot.ps1
# Description: Configures a decoy Kerberoasting Honeypot account with a fake SPN, AdminCount=1, and restricted logon capabilities.
# Target Engine: Windows PowerShell 5.1

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param()

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Configure Kerberoasting Honeypot..." -ForegroundColor Cyan

$HoneypotName = "krbtgt_honey"
$HoneypotSPN = "MSSQLSvc/sql-backup-prod.domain.local:1433"
$HoneypotDescription = "Decoy service account for backup database monitoring."

# 1. Check if the honeypot user account already exists
$ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$HoneypotName'"

if (-not $ExistingUser) {
    # Generate a complex 120-character password to prevent cracking
    $Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    $RandomPassword = ""
    for ($i = 0; $i -lt 120; $i++) {
        $Index = Get-Random -Minimum 0 -Maximum $Characters.Length
        $RandomPassword += $Characters[$Index]
    }
    
    $SecurePassword = ConvertTo-SecureString $RandomPassword -AsPlainText -Force

    # Create the AD User.
    # Set LogonWorkstations to a non-existent host to prevent logon attempts.
    # UPN domain suffix should match the root domain.
    $Domain = Get-ADDomain
    New-ADUser -Name $HoneypotName `
               -SamAccountName $HoneypotName `
               -UserPrincipalName "$HoneypotName@$($Domain.DNSRoot)" `
               -AccountPassword $SecurePassword `
               -Enabled $true `
               -Description $HoneypotDescription `
               -LogonWorkstations "HONEYPOT-VOID-HOST" `
               -PasswordNeverExpires $true

    Write-Host "[+] Decoy user account '$HoneypotName' created with logon restrictions." -ForegroundColor Green
} else {
    Write-Host "[*] Decoy user account '$HoneypotName' already exists." -ForegroundColor Yellow
}

# 2. Configure target attributes: AdminCount, ServicePrincipalName
$UserObj = Get-ADUser -Identity $HoneypotName -Properties servicePrincipalName, adminCount

# Set AdminCount to 1 (highly attractive to scanners)
if ($UserObj.adminCount -ne 1) {
    Set-ADUser -Identity $HoneypotName -Replace @{adminCount = 1}
    Write-Host "[+] Set AdminCount to 1 on '$HoneypotName'." -ForegroundColor Green
} else {
    Write-Host "[*] AdminCount is already set to 1." -ForegroundColor Yellow
}

# Set Service Principal Name
$SPNExists = $UserObj.servicePrincipalName | Where-Object { $_ -eq $HoneypotSPN }
if (-not $SPNExists) {
    Set-ADUser -Identity $HoneypotName -Add @{servicePrincipalName = $HoneypotSPN}
    Write-Host "[+] Service Principal Name '$HoneypotSPN' registered on '$HoneypotName'." -ForegroundColor Green
} else {
    Write-Host "[*] Service Principal Name '$HoneypotSPN' already registered." -ForegroundColor Yellow
}

Write-Host "Honeypot configuration applied successfully." -ForegroundColor Green
```

*To verify the honeypot configuration state:*

[Download Script: Get-KerberoastHoneypotStatus.ps1](audit_scripts/Get-KerberoastHoneypotStatus.ps1)

```powershell
# Get-KerberoastHoneypotStatus.ps1
# Description: Audits the existence, SPN, AdminCount, and logon restrictions of the Kerberoasting honeypot account.
# Target Engine: Windows PowerShell 5.1

Import-Module ActiveDirectory

Write-Host "--- Auditing Kerberoasting Honeypot Configuration ---" -ForegroundColor Cyan

$HoneypotName = "krbtgt_honey"
$HoneypotSPN = "MSSQLSvc/sql-backup-prod.domain.local:1433"

# 1. Retrieve the honeypot account
$User = Get-ADUser -Filter "SamAccountName -eq '$HoneypotName'" -Properties servicePrincipalName, adminCount, LogonWorkstations

if (-not $User) {
    Write-Host "[-] Decoy user account '$HoneypotName' does not exist." -ForegroundColor Red
    exit 1
}

$IsCompliant = $true

# 2. Verify SPN is registered
$SPNExists = $User.servicePrincipalName | Where-Object { $_ -eq $HoneypotSPN }
if ($SPNExists) {
    Write-Host "[+] Decoy SPN '$HoneypotSPN' is registered on '$HoneypotName'." -ForegroundColor Green
} else {
    Write-Host "[!] Decoy SPN '$HoneypotSPN' is NOT registered on '$HoneypotName'." -ForegroundColor Red
    $IsCompliant = $false
}

# 3. Verify AdminCount is set to 1
if ($User.adminCount -eq 1) {
    Write-Host "[+] AdminCount is set to 1 (deceptive marker active)." -ForegroundColor Green
} else {
    Write-Host "[!] AdminCount is NOT set to 1 on '$HoneypotName'." -ForegroundColor Red
    $IsCompliant = $false
}

# 4. Verify LogonWorkstations restriction
if ($User.LogonWorkstations -like "*HONEYPOT-VOID-HOST*") {
    Write-Host "[+] Logon restrictions enforced (LogonWorkstations contains 'HONEYPOT-VOID-HOST')." -ForegroundColor Green
} else {
    Write-Host "[!] Logon restrictions NOT enforced on '$HoneypotName' (LogonWorkstations: '$($User.LogonWorkstations)')." -ForegroundColor Red
    $IsCompliant = $false
}

if ($IsCompliant) {
    Write-Host "[+] Secure: Kerberoasting Honeypot is fully configured and active." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[-] Non-Compliant: Kerberoasting Honeypot configurations are incomplete." -ForegroundColor Red
    exit 1
}
```

---

## SIEM Alerting and Query Configurations

Use these reference detection logic configurations to alert on the honeypot and correlate standard ticket request events.

### 1. Honeypot Access Alerts (High Severity - Zero False Positives)

#### Splunk Query
```splunk
index=security EventCode=4769 ServiceName="sql-backup-prod"
| table _time, TargetUserName, IpAddress, ServiceName, TicketEncryptionType
```

#### Microsoft Sentinel / KQL Query
```kql
SecurityEvent
| where EventID == 4769
| where ServiceName has "sql-backup-prod"
| project TimeGenerated, TargetUserName, IpAddress, ServiceName, TicketEncryptionType
```

### 2. Anomalous Kerberoasting Request Activity (Medium Severity)

Detects users requesting a high volume of RC4 service tickets in a short period (potential Kerberoasting scans).

#### Splunk Query
```splunk
index=security EventCode=4769 TicketEncryptionType="0x17" NOT (ServiceName="*$")
| stats dc(ServiceName) as UniqueServicesRequested, values(ServiceName) as ServicesRequested by _time, TargetUserName, IpAddress
| where UniqueServicesRequested > 5
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R48 (Audit policy configuration and anomaly detection)
* **Active Directory Security Guide**: Detecting Kerberoasting Activity and Creating Service Account Honeypots (Sean Metcalf)
* **MITRE ATT&CK**: Technique T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
