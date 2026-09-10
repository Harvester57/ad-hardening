# [REQ-END-158] User Profile: Trusted Root Store Protected Roots Certificate Restriction for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-147](../../07-paws/user-profile/configure-paw-up-protected-roots.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Windows CryptoAPI Trusted Root Certification Authorities store (`Root`) defines the ultimate trust anchors for TLS/SSL communication, Kerberos PKINIT authentication, code signing, and digital identity verification. If an adversary, malicious script, or unauthorized third-party software can inject a rogue Certificate Authority (CA) into the trusted root store, the cryptographic integrity of all network communication and software trust models is completely undermined.

### 1. CryptoAPI Architecture & Root Store Protection
In default Windows configurations, users and local processes with administrative privileges can add certificates to the local computer's Trusted Root store:
* Interactive GUI prompts (the "Root Certificate Store Installation Warning") ask users to confirm certificate additions. Social engineering attacks, malicious installers, or adware frequently trick users into accepting rogue CAs.
* Once installed, a rogue root CA allows adversaries to perform transparent Adversary-in-the-Middle (AitM) TLS inspection, decrypt HTTPS enterprise traffic, forge internal domain certificates, and generate valid code signatures that deceive AppLocker, WDAC, and SmartScreen.
* Configuring `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags = 1` enforces the `CERT_PROT_ROOT_DISABLE_CURRENT_USER_FLAG` restriction. This tells the Windows Certificate Architecture to strictly block user-driven root store modifications and suppress interactive installation prompts, ensuring that only authoritative domain-level Group Policies can distribute root certificates.

### 2. Threat Vectors & Exploitation Mechanics
* **TLS Interception and Credential Theft**: Threat actors deploy localized AitM proxies that generate dynamic TLS certificates signed by an injected rogue CA. Users communicating with corporate web applications, Intranet portals, or cloud services have their session cookies and credentials decrypted without certificate mismatch warnings.
* **Bypassing Code Signing & Application Control**: An adversary with a rogue root CA in the local store can sign arbitrary malware binaries and custom drivers. The Windows kernel and security agents validate the signature as trusted, completely subverting code integrity defenses.
* **Malicious Software Bundlers & Adware**: Unapproved software suites frequently attempt to install proxy CAs to inject advertising or inspect traffic. Restricting the root store neutralizes these unauthorized modifications at the API level.

### 3. MITRE ATT&CK Mapping
* **T1553.004 - Subvert Trust Controls: Install Root Certificate**: Installing fraudulent root certificates into the trusted store to subvert verification.
* **T1557.001 - Adversary-in-the-Middle: TLS Inspection**: Intercepting and decrypting secure communications using rogue CA certificates.
* **T1556 - Modify Authentication Process**: Subverting certificate-based authentication mechanisms.

---

## Legacy Impact & Compatibility
* **Enterprise PKI Distribution**: Legitimate enterprise root CAs (Active Directory Certificate Services / Enterprise CAs) are distributed automatically via Group Policy (`Computer Configuration \ Windows Settings \ Security Settings \ Public Key Policies \ Trusted Root Certification Authorities`). This legitimate distribution mechanism remains fully functional.
* **Third-Party VPN and Proxy Software**: Enterprise VPN clients or security inspection proxies (e.g., Zscaler, Palo Alto GlobalProtect) that install root CAs must have their certificates deployed via enterprise GPO or automated device management (Intune/MECM) rather than interactive client installers.
* **Developer Workstations**: Developers generating self-signed certificates for local IIS/test hosting should install test certificates into the user-level store or utilize enterprise test CAs distributed via policy.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots`
   * **Value Name**: `Flags`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Protected Roots certificate restrictions:

[Download Script: Configure-EndAuditProtectedroots.ps1](../implementation_scripts/Configure-EndAuditProtectedroots.ps1)

```powershell
# Configure-EndAuditProtectedroots.ps1
Write-Host "Enforcing System Mitigation control: protected-roots..." -ForegroundColor Cyan

# Set Registry value: Flags
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -Value 1 -Type DWord -Force
Write-Host "    Enforced Flags = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditProtectedrootsStatus.ps1](../audit_scripts/Get-EndAuditProtectedrootsStatus.ps1)

```powershell
# Get-EndAuditProtectedrootsStatus.ps1
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
* **Microsoft Windows CryptoAPI Documentation**: Certificate Store Architecture and ProtectedRoots Registry Policy
