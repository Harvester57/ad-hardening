# [REQ-END-170] Account Policy: Disable WDigest Credential Caching for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Preferences -> Windows Settings -> Registry (or Administrative Templates -> System -> Credentials Delegation)
* **Policy Setting**: Disallow WDigest Plaintext Credential Caching (`UseLogonCredential` = `0`)
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Key & Value**:
  * `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = `0` (REG_DWORD, Disables caching plaintext passwords in LSASS memory)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1003.001: OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/), [T1556: Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)

---

## Rationale

The Local Security Authority Subsystem Service (LSASS) holds authentication tokens and session security contexts for logged-on users. Historically, the WDigest provider retained cleartext passwords in memory, exposing enterprise networks to devastating credential theft:

### Technical Threat Vectors and Defense Mechanics
1. **WDigest Authentication Protocol Flaws**:
   The WDigest Security Support Provider (`wdigest.dll`) was created to support HTTP Digest Authentication (RFC 2617). To calculate the required MD5 response hash (`username:realm:password`), the client must possess the user's plaintext password. To facilitate Single Sign-On across web resources, legacy Windows versions stored the plaintext password directly in LSASS memory upon every user logon.
2. **Defeating Memory Scraping & Mimikatz (`UseLogonCredential = 0`)**:
   Adversaries who achieve local administrative or SYSTEM execution on a workstation routinely dump the `lsass.exe` process (via tools like Mimikatz `sekurlsa::wdigest`, ProcDump, or mini-dump APIs) to harvest cleartext passwords for all logged-on domain and local users. Setting `UseLogonCredential = 0` commands the WDigest SSP to permanently cease retaining plaintext passwords in LSASS memory. Even if an attacker succeeds in dumping LSASS process memory, the WDigest password tables remain empty.
3. **Synergy with Credential Guard and LSA Protection**:
   Modern enterprise security relies on Virtualization-based Security (VBS / Credential Guard) and Protected Process Light (`RunAsPPL`) to protect LSASS. However, defense-in-depth requires that the underlying credential provider is also instructed never to cache plaintext secrets. This ensures protection remains intact during maintenance, safe boot operations, or on virtualized systems lacking nested virtualization support.
4. **Endpoint Security Posture**:
   Across Tier 2 workstations and member servers, eliminating cleartext WDigest caching prevents lateral traversal and stops attackers from capturing administrative helpdesk credentials when technicians assist end users.

---

## Legacy Impact & Compatibility

* **HTTP Digest Authentication**: Legacy intranet websites or web applications that mandate HTTP Digest authentication without support for modern Windows Integrated Authentication (Kerberos / Negotiate) will fail. Applications must be updated to support Kerberos, TLS client certificates, or SAML/OIDC federation.
* **Standard Windows Enterprise Features Unaffected**: Standard domain logons, File and Print sharing, Outlook/Exchange connectivity, and Remote Desktop sessions are unaffected by disabling WDigest caching.
* **Pre-requisites**: Supported natively on all modern Windows versions.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
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
6. Link the GPO to the appropriate workstation and member server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountWdigestCredentials.ps1](../implementation_scripts/Configure-EndAccountWdigestCredentials.ps1)

```powershell
# Configure-EndAccountWdigestCredentials.ps1
# Description: Disables WDigest plaintext credential caching in LSASS memory on Endpoints.

Write-Host "Disabling WDigest plaintext credential caching on Endpoints..." -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) {
    New-Item -Path $WDigestPath -Force | Out-Null
}
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force

Write-Host "WDigest credential caching disabled successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountWdigestCredentialsStatus.ps1](../audit_scripts/Get-EndAccountWdigestCredentialsStatus.ps1)

```powershell
# Get-EndAccountWdigestCredentialsStatus.ps1
# Description: Audits WDigest plaintext credential caching status on Endpoints.

Write-Host "--- Auditing Endpoint WDigest Credential Caching ---" -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"

if (-not (Test-Path $WDigestPath)) {
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

Verify the applied WDigest setting via command prompt:
```cmd
reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential
```
Confirm that `UseLogonCredential` is of type `REG_DWORD` with value `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.8.20.1 (Ensure 'Disallow Digest Authentication' / 'UseLogonCredential' is set to 'Disabled' [0])
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.8.20.1
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 18.8.20.1
* **DoD Windows 11 Computer STIG**: Rule SV-220798r879698_rule (Disabling WDigest authentication credentials in memory)
* **ANSSI Active Directory Hardening Guide**: Recommendations on LSASS credential protection and cleartext memory elimination
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Credentials Delegation / WDigest
* **Related Controls**: [REQ-PAW-159: Account Policy: Disable WDigest Credential Caching for PAWs](../../07-paws/account-policy/configure-paw-account-wdigest-credentials.md), [REQ-END-018: Enable LSA Protection RunAsPPL on Endpoints](../../08-endpoints/enable-lsa-protection.md)
