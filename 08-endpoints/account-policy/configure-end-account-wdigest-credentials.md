# [REQ-END-170] Account Policy: Disable WDigest Credential Caching for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\System\Credentials Delegation` or Registry Preference
  * **Registry Location**:
    * `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = `0` (REG_DWORD)

---

## Rationale
The WDigest authentication provider in legacy Windows stored cleartext passwords directly in LSASS memory. Disabling `UseLogonCredential` (`0`) ensures LSASS never caches plaintext password copies, neutralizing memory dumping tools such as Mimikatz.

---

## Legacy Impact & Compatibility
* **Digest Authentication**: Legacy applications relying on HTTP Digest authentication will fail. Modern applications must use Kerberos, OAuth/OIDC, or client certificates.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Right-click **Registry**, select **New** -> **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
   * **Value name**: `UseLogonCredential`
   * **Value type**: `REG_DWORD`
   * **Value data**: `0` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountWdigestCredentials.ps1](../implementation_scripts/Configure-EndAccountWdigestCredentials.ps1)

```powershell
# Configure-EndAccountWdigestCredentials.ps1
Write-Host "Disabling WDigest plaintext credential caching on Endpoints..." -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) { New-Item -Path $WDigestPath -Force | Out-Null }
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force

Write-Host "WDigest credential caching disabled." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountWdigestCredentialsStatus.ps1](../audit_scripts/Get-EndAccountWdigestCredentialsStatus.ps1)

```powershell
# Get-EndAccountWdigestCredentialsStatus.ps1
Write-Host "--- Auditing Endpoint WDigest Credential Caching ---" -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
$Val = (Get-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential

if ($null -ne $Val -and $Val -eq 0) {
    Write-Host "    [+] UseLogonCredential is set to 0 (Disabled)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: UseLogonCredential is '$Val' (Expected: 0)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8 (Credentials Delegation / WDigest)
* **ANSSI AD Hardening Guide**: Recommendations on LSASS credential protection and WDigest mitigation
* **DoD Windows 11 Computer STIG v2r6**: Disabling WDigest plain-text credentials in memory
