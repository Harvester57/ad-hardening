# [REQ-PAW-147] User Profile: Trusted Root Store Protected Roots Certificate Restriction for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-158](../../08-endpoints/user-profile/configure-end-up-protected-roots.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Protected Roots Store Restrictions**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots`
    * Value Name: `Flags`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Restrict root certificate additions to domain policy)

---

## Rationale
On Privileged Access Workstations (PAWs), cryptographic trust validation is paramount. Administrative sessions connect to Domain Controllers via LDAPS, manage Active Directory Certificate Services (AD CS), authenticate via smart cards / Windows Hello for Business, and execute digitally signed PowerShell scripts. Allowing any local or interactive addition of root certificates to the PAW root store creates a catastrophic risk of rogue CA insertion, enabling transparent interception of Tier 0 authentication traffic.

### 1. CryptoAPI Architecture & Root Store Protection
The Windows CryptoAPI subsystem maintains the `Root` certificate store as the ultimate trust anchor for the system:
* When establishing an encrypted management session (e.g., LDAPS over port 636, WinRM over HTTPS, or MMC snap-ins), the client verifies the target server's certificate against the trusted root CAs.
* In default configurations, local administrators or interactive prompts can add certificates to the computer root store. If a threat actor compromises a low-privilege service or induces an administrator to run an unvetted package, a rogue root CA can be planted.
* With a rogue root CA installed on the PAW, an adversary on the local network can spoof Domain Controllers, decrypt and tamper with LDAPS management sessions, intercept Kerberos PKINIT exchanges, and capture domain administrative hashes.
* Configuring `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags = 1` enforces strict policy control: all interactive root store installation dialogs are suppressed, and the root store is made immutable to local users, ensuring that only authoritative Domain Group Policy can deploy root certificates.

### 2. Tier 0 Threat Vectors & PAW Isolation
* **Adversary-in-the-Middle on Administrative Traffic**: Prevents rogue root certificates from intercepting TLS traffic between the PAW and Tier 0 Domain Controllers, Entra ID Connect, or HSM management consoles.
* **Integrity of Code Signing Allowlisting**: PAWs enforce strict Windows Defender Application Control (WDAC) policies anchored in cryptographic signatures. Restricting root store additions guarantees that an attacker cannot validate malicious binaries by importing a self-signed root certificate.
* **Auditability & Centralized PKI Governance**: All trusted root certificates on PAWs must originate exclusively from the vetted corporate PKI deployed via Active Directory Group Policy.

### 3. MITRE ATT&CK Mapping
* **T1553.004 - Subvert Trust Controls: Install Root Certificate**: Installing fraudulent root certificates into the trusted store to subvert verification.
* **T1557.001 - Adversary-in-the-Middle: TLS Inspection**: Intercepting and decrypting secure administrative communications using rogue CA certificates.
* **T1556 - Modify Authentication Process**: Subverting certificate-based administrative authentication mechanisms.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs do not require ad-hoc root certificate imports, self-signed test certificates, or third-party SSL inspection proxies. All necessary root certificates are distributed centrally via Active Directory GPO.
* **Zero Operational Disruption**: Legitimate administrative operations, LDAPS connections, and smart card logons operate with zero disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots`
   * **Value Name**: `Flags`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Protected Roots certificate restrictions on the PAW console:

[Download Script: Configure-PawAuditProtectedroots.ps1](../implementation_scripts/Configure-PawAuditProtectedroots.ps1)

```powershell
# Configure-PawAuditProtectedroots.ps1
Write-Host "Enforcing System Mitigation control: protected-roots..." -ForegroundColor Cyan

# Set Registry value: Flags
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -Value 1 -Type DWord -Force
Write-Host "    Enforced Flags = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditProtectedrootsStatus.ps1](../audit_scripts/Get-PawAuditProtectedrootsStatus.ps1)

```powershell
# Get-PawAuditProtectedrootsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: Flags
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.Flags -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000115, Windows 11 STIG Rule WN11-CC-000115
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and Public Key Infrastructure root stores)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
