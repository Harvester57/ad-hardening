# Module 2: Domain Controller Hardening

This module defines the hardening requirements for **Windows Server 2016 Domain Controllers (DCs)**. Domain Controllers are the heart of the Active Directory trust boundary (Tier 0). Implementing operating system-level hardening is critical to prevent credential compromise and directory manipulation.

---

## 1. Disabling Legacy Protocols

Legacy protocols introduce substantial vulnerabilities like spoofing, relay attacks, and remote code execution. In a modern AD environment, the following must be disabled:

### SMBv1
* **Risk**: SMBv1 is highly vulnerable to remote exploit (e.g., EternalBlue). It lacks encryption, message signing robustness, and integrity checks.
* **Requirement**: Complete removal or disabling of the SMB 1.0/CIFS File Sharing Support feature.

### LLMNR, NetBIOS Name Service (NBT-NS), and mDNS
* **Risk**: These multicast name resolution protocols are used when DNS resolution fails. Attackers can spoof responses to capture user credentials (NTLMv2 hashes) via tools like Responder.
* **Requirement**: Disable LLMNR via GPO, and disable NetBIOS on all active network adapters.

### NTLMv1
* **Risk**: NTLMv1 authentication uses weak cryptographic hashes that can be decrypted offline in minutes.
* **Requirement**: Restrict NTLM authentication to NTLMv2 or Kerberos only.

---

## 2. LDAP Signing and Channel Binding

Unencrypted LDAP (TCP/389) communications are vulnerable to eavesdropping and man-in-the-middle (MitM) replay attacks.

### LDAP Signing (ANSSI R19)
* **Requirement**: Domain Controllers must be configured to require LDAP signing for all LDAP traffic over cleartext. Clients must also be configured to negotiate signing.

### LDAP Channel Binding (ANSSI R20)
* **Requirement**: Enforce LDAP Channel Binding tokens (CBT) over secure LDAP (LDAPS - TCP/636). CBT binds the TLS session layer with the SASL authentication layer, completely preventing credential relay attacks.

---

## 3. Credential Protection (LSA Protection & Credential Guard)

Attackers seek to extract credentials from the Local Security Authority Subsystem Service (LSASS) memory.

### LSA Protection
* **Requirement**: Force LSASS to run as a Protected Process Light (PPL) (`RunAsPPL` = 1). This prevents non-protected processes (even running as SYSTEM) from reading its memory or injecting code.

### Virtualization-Based Security (VBS) & Credential Guard
* **Requirement**: Enable Windows Defender Credential Guard. Credential Guard uses virtualization to isolate secret keys and NTLM credentials in a secure virtualization container (VBS), making them inaccessible to LSASS memory dumps.

---

## 4. Disabling the Print Spooler Service on DCs

* **Risk**: The Windows Print Spooler service runs by default on Domain Controllers. Attackers can exploit it to execute remote code (e.g., PrintNightmare) or coercion attacks (e.g., the PetitPotam technique, where a DC is forced to authenticate to a malicious listener using NTLM, leading to immediate domain takeovers via NTLM relaying to AD Certificate Services).
* **Requirement**: Stop and permanently disable the `Spooler` service on all Domain Controllers.

---

## PowerShell Implementation Guide

### 1. Auditing Domain Controller Security Configurations (Audit)

Run this script locally on a Domain Controller to audit the status of legacy protocols, LDAP requirements, LSA protection, and the Print Spooler service.

```powershell
# Audit-DCHardening.ps1
# Audits the local DC configuration against security baseline requirements.

Write-Host "--- Auditing Domain Controller Hardening Status ---" -ForegroundColor Cyan

# 1. Audit Print Spooler Service
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler) {
    $spoolerColor = if ($spooler.Status -eq "Stopped" -and $spooler.StartType -eq "Disabled") { "Green" } else { "Red" }
    Write-Host "[*] Print Spooler Status: $($spooler.Status) | Startup Type: $($spooler.StartType)" -ForegroundColor $spoolerColor
} else {
    Write-Host "[+] Print Spooler service not found (Safe)." -ForegroundColor Green
}

# 2. Audit SMBv1 State
$smbConfig = Get-SmbServerConfiguration
$smbColor = if ($smbConfig.EnableSMB1Protocol -eq $false) { "Green" } else { "Red" }
Write-Host "[*] SMBv1 Protocol Enabled: $($smbConfig.EnableSMB1Protocol)" -ForegroundColor $smbColor

# 3. Audit LDAP Signing & Channel Binding
# Path: HKLM:\System\CurrentControlSet\Services\NTDS\Parameters
$ntdsRegPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (Test-Path $ntdsRegPath) {
    $ldapServerIntegrity = Get-ItemProperty -Path $ntdsRegPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
    $ldapIntegrityVal = if ($ldapServerIntegrity) { $ldapServerIntegrity.LDAPServerIntegrity } else { 0 }
    # 2 = Require Signing
    $integrityColor = if ($ldapIntegrityVal -eq 2) { "Green" } else { "Red" }
    Write-Host "[*] LDAP Server Integrity (Signing): $ldapIntegrityVal (Required = 2)" -ForegroundColor $integrityColor

    $ldapCbtVal = Get-ItemProperty -Path $ntdsRegPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
    $cbtVal = if ($ldapCbtVal) { $ldapCbtVal.LdapEnforceChannelBinding } else { 0 }
    # 1 = Enabled (if supported), 2 = Required (Always)
    $cbtColor = if ($cbtVal -eq 2) { "Green" } else { "Red" }
    Write-Host "[*] LDAP Channel Binding (CBT): $cbtVal (Required = 2)" -ForegroundColor $cbtColor
} else {
    Write-Warning "NTDS Parameters registry path not found. Is this machine a Domain Controller?"
}

# 4. Audit LSA Protection (RunAsPPL)
$lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaPpl = Get-ItemProperty -Path $lsaRegPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
$lsaPplVal = if ($lsaPpl) { $lsaPpl.RunAsPPL } else { 0 }
$lsaColor = if ($lsaPplVal -eq 1) { "Green" } else { "Red" }
Write-Host "[*] LSA Protection (RunAsPPL): $lsaPplVal (Enabled = 1)" -ForegroundColor $lsaColor

# 5. Audit NTLMv1 restrictions
$ntlmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lmCompatibility = Get-ItemProperty -Path $ntlmRegPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
$lmVal = if ($lmCompatibility) { $lmCompatibility.LmCompatibilityLevel } else { 0 }
# 5 = Refuse LM & NTLMv1, use only NTLMv2
$lmColor = if ($lmVal -eq 5) { "Green" } else { "Red" }
Write-Host "[*] LM Compatibility Level (NTLMv1 restriction): $lmVal (Required = 5)" -ForegroundColor $lmColor
```

### 2. Remediating Domain Controller Configurations (Remediation)

Execute the following PowerShell script to enforce the security configurations on the local Domain Controller. Run this script in an administrative PowerShell session.

```powershell
# Set-DCHardeningRemediation.ps1
# Configures local DC OS settings, disables SMBv1, disables Print Spooler,
# enforces LDAP signing/channel binding, NTLMv2 only, and LSA Protection.

Write-Host "--- Applying DC Hardening Remediation ---" -ForegroundColor Cyan

# 1. Stop and Disable Print Spooler Service
Write-Host "[+] Hardening Print Spooler service..." -ForegroundColor Gray
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler) {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service -Name Spooler -StartupType Disabled
    Write-Host "    Print Spooler has been disabled." -ForegroundColor Green
}

# 2. Disable SMBv1
Write-Host "[+] Disabling SMBv1 protocol..." -ForegroundColor Gray
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Write-Host "    SMBv1 disabled." -ForegroundColor Green

# 3. Enforce LDAP Server Signing (LDAPServerIntegrity = 2) and Channel Binding (LdapEnforceChannelBinding = 2)
Write-Host "[+] Enforcing LDAP Signing and Channel Binding..." -ForegroundColor Gray
$ntdsRegPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (-not (Test-Path $ntdsRegPath)) {
    New-Item -Path $ntdsRegPath -Force | Out-Null
}
Set-ItemProperty -Path $ntdsRegPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord
Set-ItemProperty -Path $ntdsRegPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
Write-Host "    LDAP signing and channel binding requirements enforced." -ForegroundColor Green

# 4. Enforce NTLMv2 Only (LmCompatibilityLevel = 5)
Write-Host "[+] Configuring NTLMv1 restrictions..." -ForegroundColor Gray
$lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaRegPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Write-Host "    NTLMv1 disabled (LM Compatibility Level set to 5)." -ForegroundColor Green

# 5. Enable LSA Protection (RunAsPPL = 1)
Write-Host "[+] Enabling LSA Protection (RunAsPPL)..." -ForegroundColor Gray
Set-ItemProperty -Path $lsaRegPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "    LSA Protection enabled. (A reboot is required to activate this change)." -ForegroundColor Green

Write-Host "`nRemediation completed. Please reboot the system to apply all changes (especially LSA Protection)." -ForegroundColor Cyan
```
