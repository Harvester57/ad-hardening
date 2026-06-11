# Hardening Requirement: Enforce User and Service Account Kerberos Encryption (AES-Only)

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Account Attribute: `msDS-SupportedEncryptionTypes` (Set to `24`)

---

## Rationale
In Active Directory, even when Group Policies restrict Kerberos encryption algorithms on domain members, individual user and service accounts can override these restrictions during authentication negotiation. If an account has obsolete encryption types enabled (e.g., RC4 or DES) or has the `msDS-SupportedEncryptionTypes` attribute set to `0` (default, which defaults to domain controllers' allowed options), the Key Distribution Center (KDC) may issue Service tickets (TGS) using the RC4 algorithm.

Because RC4 utilizes weaker, legacy cryptography, tickets encrypted using RC4 can be easily extracted and cracked offline (Kerberoasting) by adversaries. Explicitly configuring the `msDS-SupportedEncryptionTypes` attribute to `24` (AES128 = 8 + AES256 = 16) on Active Directory accounts ensures that the KDC only negotiates AES encryption types, securing the authentication credentials against offline brute-forcing and ticket forgery.

---

## Legacy Impact & Compatibility
* **Client and Service Compatibility**: Host systems running services under these accounts, as well as the clients connecting to them, must support AES Kerberos encryption. Windows 7/Server 2008 and newer support AES natively.
* **Pre-remediation Audit**: Ensure that any legacy non-Windows servers (e.g., older UNIX/Linux systems running Samba or Java applications) are verified to support AES Kerberos encryption before enforcing this setting.

---

## Implementation Steps

### Option A: Active Directory Users and Computers Attribute Editor (Preferred)

1. Open **Active Directory Users and Computers** (`dsa.msc`).
2. Select **View** from the menu bar and check **Advanced Features**.
3. Locate the target user or service account.
4. Right-click the object and select **Properties**.
5. Navigate to the **Attribute Editor** tab.
6. Scroll down and double-click the `msDS-SupportedEncryptionTypes` attribute.
7. Set the value to `24` (Decimal) and click **OK**.
8. Go to the **Account** tab and verify that under **Account options**, `This account supports Kerberos AES 128 bit encryption` and `This account supports Kerberos AES 256 bit encryption` are checked, while RC4/DES are not forced.
9. Click **Apply** and then **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to enforce AES-only encryption on active user accounts in the domain.

```powershell
# Set-AccountAESEncryption.ps1
# Description: Configures the msDS-SupportedEncryptionTypes attribute to AES-only (24) on active user accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce AES-Only Kerberos Encryption on Accounts..." -ForegroundColor Cyan

# 24 represents AES128 (8) + AES256 (16)
$AESValue = 24
$TargetUsers = Get-ADUser -Filter {Enabled -eq $true}

foreach ($User in $TargetUsers) {
    # Retrieve current attribute value
    $currUser = Get-ADUser -Identity $User -Properties msDS-SupportedEncryptionTypes
    $currVal = $currUser."msDS-SupportedEncryptionTypes"
    
    if ($currVal -ne $AESValue) {
        Write-Host "[*] Enforcing AES encryption on account: $($User.SamAccountName)" -ForegroundColor Gray
        Set-ADUser -Identity $User -Replace @{"msDS-SupportedEncryptionTypes" = $AESValue}
    }
}

Write-Host "AES encryption has been successfully enforced on active accounts." -ForegroundColor Green
```

*To audit account Kerberos encryption configuration:*
```powershell
# Get-AccountEncryptionStatus.ps1
# Description: Identifies accounts that do not have msDS-SupportedEncryptionTypes set to 24 (AES-only).

Import-Module ActiveDirectory

Write-Host "--- Auditing Account Kerberos Encryption Configuration ---" -ForegroundColor Cyan

$VulnerableAccounts = Get-ADUser -Filter {Enabled -eq $true} -Properties msDS-SupportedEncryptionTypes | Where-Object { $_."msDS-SupportedEncryptionTypes" -ne 24 }

if ($VulnerableAccounts) {
    Write-Host "[!] Accounts not configured for AES-only (msDS-SupportedEncryptionTypes != 24):" -ForegroundColor Red
    foreach ($Acct in $VulnerableAccounts) {
        $Val = $Acct."msDS-SupportedEncryptionTypes"
        if ($null -eq $Val) { $Val = "Not Set (0)" }
        Write-Host "    - $($Acct.SamAccountName) | Value: $Val" -ForegroundColor White
    }
} else {
    Write-Host "[+] Secure: All active accounts are configured for AES-only Kerberos encryption." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete encryption algorithms)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section on Kerberos Encryption Strength
* **Microsoft Security Guidance**: Decrypting the Selection of Supported Kerberos Encryption Types
