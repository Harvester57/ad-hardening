# [REQ-DC-014] Restrict NTLM

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policies**:
    * `Network security: Restrict NTLM: Audit NTLM authentication in this domain`
    * `Network security: Restrict NTLM: NTLM authentication in this domain`
    * `Network security: Restrict NTLM: Audit Incoming NTLM Traffic`
    * `Network security: Restrict NTLM: Incoming NTLM Traffic`
    * `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers`
    * `Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication`
  * **Registry Location**:
    * `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` -> `AuditNTLMInDomain` = `7` (REG_DWORD)
    * `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` -> `RestrictNTLMInDomain` = `3` (REG_DWORD)
    * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` -> `AuditReceivingNTLMTraffic` = `2` (REG_DWORD)
    * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` -> `RestrictReceivingNTLMTraffic` = `2` (REG_DWORD)
    * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` -> `RestrictSendingNTLMTraffic` = `2` (REG_DWORD)

---

## Rationale
The NT LAN Manager (NTLM) authentication protocol is legacy, cryptographically weak, and lacks support for modern security primitives such as mutual authentication. Adversaries exploit NTLM through credential relaying attacks (e.g., replaying captured authentication responses to other network services) and coercion techniques (e.g., PetitPotam or printer spooler RPC abuse).

By auditing and subsequently restricting NTLM authentication incoming to, outgoing from, and within the Active Directory domain, organizations significantly mitigate the risks of credential relaying, offline password cracking, and unauthorized lateral movement. Restricting NTLM pushes client machines and application servers to utilize Kerberos, which provides robust mutual authentication and support for advanced cryptographic algorithms. Microsoft has also announced the eventual deprecation of NTLM, making active restriction an essential step in future-proofing active directory directory services.

---

## Legacy Impact & Compatibility
* **Auditing Requirement**: Administrators must enable auditing policies prior to enforcing restriction policies. Review the operational logs at `Applications and Services Logs > Microsoft > Windows > NTLM > Operational` for Event ID `8004` (Domain Controller NTLM validation), `8001` (incoming NTLM block auditing), and `8003` (outgoing NTLM block auditing) to identify legitimate business applications requiring NTLM.
* **Authentication Failures**: Hard enforcement of NTLM restrictions will block applications that use hardcoded IP addresses (preventing Kerberos SPN mapping), non-domain joined assets, and legacy appliances.
* **Exceptions**: Remote servers that cannot be transitioned to Kerberos must be explicitly added to the GPO exception list (`Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication`) to prevent application outages.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Phase 1: Enable Auditing (Apply to Domain Controllers, Servers, and Clients)
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following audit policies:
   * **Policy**: `Network security: Restrict NTLM: Audit NTLM authentication in this domain`
     * **Setting**: `Enable all` (Apply to Domain Controllers)
   * **Policy**: `Network security: Restrict NTLM: Audit Incoming NTLM Traffic`
     * **Setting**: `Enable auditing for all accounts` (Apply to DCs, member servers, and clients)
   * **Policy**: `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers`
     * **Setting**: `Audit all` (Apply to DCs, member servers, and clients)

#### Phase 2: Enforce Restrictions (Apply after logs have been verified and exception lists populated)
1. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Configure the following restriction policies:
   * **Policy**: `Network security: Restrict NTLM: NTLM authentication in this domain`
     * **Setting**: `Deny for domain accounts` (Apply to Domain Controllers)
   * **Policy**: `Network security: Restrict NTLM: Incoming NTLM Traffic`
     * **Setting**: `Deny all accounts` (Apply to member servers and clients)
   * **Policy**: `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers`
     * **Setting**: `Deny all` (Apply to member servers and clients)
   * **Policy**: `Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication`
     * **Setting**: Configure the server hostnames or FQDNs that require exemption.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing or standalone systems) or if the control is not manageable via standard GPO GUI interfaces.

[Download Script: Configure-RestrictNTLM.ps1](implementation_scripts/Configure-RestrictNTLM.ps1)

```powershell
# Configure-RestrictNTLM.ps1
# Description: Configures local registry values to enforce NTLM restrictions and auditing.

Write-Host "Applying hardening requirement: Restrict NTLM..." -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# Ensure LSA MSV1_0 path exists and apply settings
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}

Set-ItemProperty -Path $LsaPath -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "RestrictReceivingNTLMTraffic" -Value 2 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord

# Ensure Netlogon Parameters path exists and apply settings
if (-not (Test-Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}

Set-ItemProperty -Path $NetlogonPath -Name "AuditNTLMInDomain" -Value 7 -Type DWord
Set-ItemProperty -Path $NetlogonPath -Name "RestrictNTLMInDomain" -Value 3 -Type DWord

Write-Host "NTLM restriction registry configurations applied successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-RestrictNTLMStatus.ps1](audit_scripts/Get-RestrictNTLMStatus.ps1)

```powershell
# Get-RestrictNTLMStatus.ps1
# Description: Audits the registry configuration for NTLM auditing and restrictions.

Write-Host "--- Auditing NTLM Restrictions ---" -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

if (Test-Path $LsaPath) {
    $AuditRecv = Get-ItemProperty -Path $LsaPath -Name "AuditReceivingNTLMTraffic" -ErrorAction SilentlyContinue
    if ($AuditRecv) {
        Write-Host "[+] AuditReceivingNTLMTraffic is set to $($AuditRecv.AuditReceivingNTLMTraffic) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: AuditReceivingNTLMTraffic is not configured." -ForegroundColor Red
    }

    $RestrictRecv = Get-ItemProperty -Path $LsaPath -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue
    if ($RestrictRecv) {
        Write-Host "[+] RestrictReceivingNTLMTraffic is set to $($RestrictRecv.RestrictReceivingNTLMTraffic) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictReceivingNTLMTraffic is not configured." -ForegroundColor Red
    }

    $RestrictSend = Get-ItemProperty -Path $LsaPath -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
    if ($RestrictSend) {
        Write-Host "[+] RestrictSendingNTLMTraffic is set to $($RestrictSend.RestrictSendingNTLMTraffic) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictSendingNTLMTraffic is not configured." -ForegroundColor Red
    }
} else {
    Write-Host "[!] LSA MSV1_0 path does not exist." -ForegroundColor Red
}

if (Test-Path $NetlogonPath) {
    $AuditDomain = Get-ItemProperty -Path $NetlogonPath -Name "AuditNTLMInDomain" -ErrorAction SilentlyContinue
    if ($AuditDomain) {
        Write-Host "[+] AuditNTLMInDomain is set to $($AuditDomain.AuditNTLMInDomain) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: AuditNTLMInDomain is not configured." -ForegroundColor Red
    }

    $RestrictDomain = Get-ItemProperty -Path $NetlogonPath -Name "RestrictNTLMInDomain" -ErrorAction SilentlyContinue
    if ($RestrictDomain) {
        Write-Host "[+] RestrictNTLMInDomain is set to $($RestrictDomain.RestrictNTLMInDomain) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictNTLMInDomain is not configured." -ForegroundColor Red
    }
} else {
    Write-Host "[!] Netlogon Parameters path does not exist." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete and insecure protocols)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.7.5 to 2.3.7.9 (Restrict NTLM policies)
* **Microsoft Security Guidance**: Restrict NTLM Audit and Restrict Policies
