# Hardening Requirement: Restrict Kerberos Encryption Types

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Network security: Configure encryption types allowed for Kerberos`
  * **Setting**: `AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types` (Make sure DES and RC4 are unchecked)
  * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` -> `SupportedEncryptionTypes` = `2147483640` (REG_DWORD, decimal representation of `0x7FFFFFF8` or `0x7FFFFFC0` which restricts to AES and future types)

---

## Rationale
Active Directory uses Kerberos as its primary authentication protocol. By default, older cryptographic algorithms such as Data Encryption Standard (DES) and Rivest Cipher 4 (RC4) are supported for compatibility reasons.

RC4-HMAC uses MD4 and MD5 hashing, which are cryptographically broken. When RC4 is enabled, adversaries can perform Kerberoasting attacks (requesting Service Principal Name - SPN - tickets from the domain) and easily crack the resulting tickets offline using GPU arrays. Similarly, DES is vulnerable to brute-force cracking.

Restricting allowed Kerberos encryption types to Advanced Encryption Standard (AES-128 and AES-256) forces the Kerberos Key Distribution Center (KDC) on Domain Controllers and the local systems to negotiate only AES encryption. This significantly increases the cryptographic strength of Kerberos tickets, making offline password extraction (Kerberoasting) or golden ticket forgery highly difficult.

---

## Legacy Impact & Compatibility
* **Account Compatibility**: User and computer accounts in Active Directory must support AES encryption. If a legacy service account does not have "This account supports Kerberos AES 128 bit/256 bit encryption" checked in its account options in Active Directory, authentication will fail once RC4 is disabled.
* **Domain Trust Impact**: If the domain is joined in a trust relationship with an external domain (e.g., legacy MIT Kerberos realms or older Windows forests) that does not support AES, trust authentication will fail.
* **Pre-remediation Audit**: Administrators should query the active directory environment for accounts that do not support AES using PowerShell:
  `Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { -not $_."msDS-SupportedEncryptionTypes" }`
  Ensure these accounts are updated to support AES before enforcing this control.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Network security: Configure encryption types allowed for Kerberos`
   * **Setting**: Check only the following boxes:
     * `AES128_HMAC_SHA1`
     * `AES256_HMAC_SHA1`
     * `Future encryption types`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

```powershell
# Configure-KerberosEncryptionTypes.ps1
# Description: Restricts Kerberos encryption types to AES128, AES256, and Future types.

Write-Host "Applying hardening requirement: Restrict Kerberos Encryption Types..." -ForegroundColor Cyan

$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# 2147483640 (0x7FFFFFF8) enables AES128, AES256, and Future encryption types
Set-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord
Write-Host "Kerberos encryption types restricted to AES and future types." -ForegroundColor Green
```

*To verify the setting has been applied:*
```powershell
# Get-KerberosEncryptionStatus.ps1
# Description: Audits the allowed Kerberos encryption types in the registry.

Write-Host "--- Auditing Kerberos Encryption Types ---" -ForegroundColor Cyan

$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$regVal = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue

if ($regVal) {
    $encTypes = $regVal.SupportedEncryptionTypes
    
    # Check if weak algorithms are enabled (DES = 0x1, 0x2; RC4 = 0x4)
    $hasDES = ($encTypes -band 0x1) -or ($encTypes -band 0x2)
    $hasRC4 = ($encTypes -band 0x4)
    $hasAES128 = ($encTypes -band 0x8)
    $hasAES256 = ($encTypes -band 0x10)
    
    if ($hasDES -or $hasRC4) {
        Write-Host "[!] VULNERABLE: Weak Kerberos encryption algorithms are allowed (DES: $($hasDES), RC4: $($hasRC4)). SupportedEncryptionTypes raw value: $($encTypes)." -ForegroundColor Red
    } else {
        if ($hasAES128 -and $hasAES256) {
            Write-Host "[+] Kerberos encryption is secure. Restricting to AES128/AES256 (SupportedEncryptionTypes: $($encTypes))." -ForegroundColor Green
        } else {
            Write-Host "[-] Kerberos encryption configuration is custom. AES128: $($hasAES128), AES256: $($hasAES256) (SupportedEncryptionTypes: $($encTypes))." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[!] VULNERABLE: SupportedEncryptionTypes registry value is missing. Default behavior allows insecure RC4." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete and insecure protocols)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.7.5 (Ensure 'Network security: Configure encryption types allowed for Kerberos' is configured)
* **Microsoft Security Guidance**: Decrypting the Selection of Supported Kerberos Encryption Types
