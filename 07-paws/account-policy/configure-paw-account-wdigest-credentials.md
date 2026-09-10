# [REQ-PAW-159] Account Policy: Disable WDigest Credential Caching for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Preferences -> Windows Settings -> Registry (or Administrative Templates -> System -> Credentials Delegation)
* **Policy Setting**: Disallow WDigest Plaintext Credential Caching (`UseLogonCredential` = `0`)
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Key & Value**:
  * `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = `0` (REG_DWORD, Disables caching plaintext passwords in LSASS memory)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1003.001: OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/), [T1556: Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)

---

## Rationale

The Local Security Authority Subsystem Service (LSASS) manages active logon sessions and authentication tokens. In legacy Windows architectures, the WDigest provider retained cleartext passwords in memory, creating one of the most prolific post-exploitation attack vectors in Windows history:

### Technical Threat Vectors and Defense Mechanics
1. **WDigest Protocol Design and Plaintext Memory Retention**:
   The WDigest Security Support Provider (`wdigest.dll`) was implemented to support HTTP Digest Authentication (RFC 2617). Because Digest authentication requires computing an MD5 hash over `username:realm:password`, the client cannot generate the digest response using an NTLM hash or Kerberos ticket—it requires access to the raw password string. To provide seamless Single Sign-On (SSO) for web applications, Windows historically cached the user's plaintext password directly in LSASS process memory upon every interactive, remote desktop, or network logon.
2. **Eliminating In-Memory Credential Dumping (`UseLogonCredential = 0`)**:
   Threat tools like Mimikatz gained widespread notoriety through the `sekurlsa::wdigest` command, which traverses LSASS memory structures (`wdigest!lConnectList`) to extract plaintext passwords of every active or disconnected user session. Setting `UseLogonCredential = 0` commands the WDigest SSP to never retain plaintext credentials in LSASS memory. When an attacker attempts an LSASS memory dump or memory scraping attack, the WDigest credential structures return null fields (`Password: (null)`).
3. **Defense-in-Depth Layering with Credential Guard & RunAsPPL**:
   While modern security baselines enable Virtualization-based Security (Credential Guard) and LSA Protection (`RunAsPPL`), explicit registry lockdown of `UseLogonCredential = 0` remains essential. This prevents registry tampering, legacy fallbacks during safe mode operations, or credential leakage if hypervisor protections are temporarily unavailable.
4. **Tier 0 PAW Isolation Posture**:
   On Privileged Access Workstations, administrators log on with enterprise directory authority. Retaining even a temporary plaintext password copy of a Tier 0 administrator in workstation memory creates an unacceptable risk of total forest compromise. WDigest caching must be permanently disabled.

---

## Legacy Impact & Compatibility

* **HTTP Digest Authentication Inoperability**: Web applications or legacy intranets that rely strictly on HTTP Digest authentication without Kerberos or TLS client certificates will fail to authenticate silently. Such legacy applications must be modernized to use Kerberos (Negotiate / SPNEGO), SAML, or modern OAuth 2.0 / OpenID Connect authentication.
* **Standard Windows Domain Operations Unaffected**: Kerberos and NTLMv2 domain authentication, RDP sessions, and administrative tooling (PowerShell, RSAT, MMC) do not utilize WDigest and operate normally.
* **Pre-requisites**: Supported on all Windows 10/11 Enterprise builds natively.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Right-click **Registry**, select **New** -> **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
   * **Value name**: `UseLogonCredential`
   * **Value type**: `REG_DWORD`
   * **Value data**: `0` (Decimal)
5. Click **Apply**, then **OK**.
6. Link the GPO to the dedicated PAW OU and force replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountWdigestCredentials.ps1](../implementation_scripts/Configure-PawAccountWdigestCredentials.ps1)

```powershell
# Configure-PawAccountWdigestCredentials.ps1
# Description: Disables WDigest plaintext credential caching in LSASS memory on PAWs.

Write-Host "Disabling WDigest plaintext credential caching on PAWs..." -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) {
    New-Item -Path $WDigestPath -Force | Out-Null
}
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force

Write-Host "WDigest credential caching disabled successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountWdigestCredentialsStatus.ps1](../audit_scripts/Get-PawAccountWdigestCredentialsStatus.ps1)

```powershell
# Get-PawAccountWdigestCredentialsStatus.ps1
# Description: Audits WDigest plaintext credential caching status on PAWs.

Write-Host "--- Auditing PAW WDigest Credential Caching ---" -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"

if (-not (Test-Path -Path $WDigestPath)) {
    Write-Host "    [!] MISSING KEY: $WDigestPath" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}

$Val = (Get-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential

if ($null -ne $Val -and $Val -eq 0) {
    Write-Host "    [+] UseLogonCredential is set to 0 (Disabled - Secure)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: UseLogonCredential is '$Val' (Expected: 0)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
```

---

### Option C: Manual Verification

Verify the applied WDigest setting using command prompt:
```cmd
reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential
```
Confirm that `UseLogonCredential` is of type `REG_DWORD` with a value of `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.8.20.1 (Ensure 'Disallow Digest Authentication' / 'UseLogonCredential' is set to 'Disabled' [0])
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.8.20.1
* **DoD Windows 11 Computer STIG**: Rule SV-220798r879698_rule (Disabling WDigest authentication credentials in memory)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (LSASS Memory Protection and Elimination of In-Memory Cleartext Credentials)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Credentials Delegation / WDigest
* **Related Controls**: [REQ-END-170: Account Policy: Disable WDigest Credential Caching for Endpoints](../../08-endpoints/account-policy/configure-end-account-wdigest-credentials.md), [REQ-PAW-023: Enable LSA Protection RunAsPPL on PAWs](../../07-paws/enable-lsa-protection.md)
