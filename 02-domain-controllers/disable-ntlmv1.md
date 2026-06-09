# Hardening Requirement: Disable NTLMv1

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Network security: LAN Manager authentication level`
  * **Setting**: `Send NTLMv2 response only. Refuse LM & NTLM`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` -> `LmCompatibilityLevel` = `5` (REG_DWORD)

---

## Rationale
NTLMv1 (NT LAN Manager version 1) is a legacy authentication protocol that relies on weak cryptographic primitives (specifically MD4 and DES). Because of these mathematical weaknesses, an attacker who intercepts NTLMv1 network authentication traffic can decrypt the responses offline in a matter of minutes, recovering the user's plaintext password or NT hash.

By configuring the system to send only NTLMv2 responses and refuse both LM and NTLMv1 negotiations (corresponding to LAN Manager Compatibility Level 5), the system enforces the use of NTLMv2, which implements HMAC-MD5 and provides significantly stronger protection against offline cryptographic analysis. It also ensures that the directory environment moves closer to Kerberos-exclusive authentication.

---

## Legacy Impact & Compatibility
* **Legacy Clients**: Operating systems older than Windows 7 / Windows Server 2008 R2, along with outdated non-Windows systems (such as older Samba integrations, legacy network scanners, or ancient printers), might not support NTLMv2. Disabling NTLMv1 will block these systems from authenticating.
* **Pre-remediation Audit**: Before applying this control, administrators should monitor NTLMv1 authentications by checking the Windows Security Log (Event ID 4624, checking the authentication package details) or enabling NTLM auditing via GPO (`Network security: Restrict NTLM: Audit NTLM authentication in this domain`).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Network security: LAN Manager authentication level`
   * **Setting**: `Send NTLMv2 response only. Refuse LM & NTLM`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

```powershell
# Configure-DisableNTLMv1.ps1
# Description: Restricts NTLM authentication to NTLMv2 and refuses NTLMv1 / LM.

Write-Host "Applying hardening requirement: Disable NTLMv1..." -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Write-Host "LM Compatibility Level set to 5 (Send NTLMv2 response only. Refuse LM & NTLM)." -ForegroundColor Green
```

*To verify the setting has been applied:*
```powershell
# Get-NTLMv1Status.ps1
# Description: Audits the LM Compatibility Level setting in the registry.

Write-Host "--- Auditing NTLMv1 Restriction ---" -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaReg = Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

if ($lsaReg) {
    $lmVal = $lsaReg.LmCompatibilityLevel
    if ($lmVal -eq 5) {
        Write-Host "[+] NTLMv1 is disabled. LM Compatibility Level is set to $($lmVal) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: LM Compatibility Level is set to $($lmVal) (Required: 5)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: LmCompatibilityLevel key is missing. System is using the default value (allows NTLMv1)." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete and insecure protocols)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.7.4 (Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM')
* **Microsoft Security Guidance**: LAN Manager Authentication Level configurations
