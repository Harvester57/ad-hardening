# [REQ-PAW-159] Account Policy: Disable WDigest Credential Caching for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\System\Credentials Delegation` or Registry Preference
  * **Registry Location**:
    * `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = `0` (REG_DWORD)

---

## Rationale
The WDigest authentication provider in older Windows releases stored plain-text passwords directly in LSASS memory to support HTTP Digest authentication. Disabling `UseLogonCredential` (`0`) ensures that LSASS never retains plaintext password copies in memory, mitigating credential theft via memory dumping tools such as Mimikatz.

---

## Legacy Impact & Compatibility
* **Digest Authentication**: Applications requiring WDigest HTTP authentication will fail. Modern environments use Kerberos, TLS client certificates, or modern OAuth/OIDC tokens.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
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

[Download Script: Configure-PawAccountWdigestCredentials.ps1](../implementation_scripts/Configure-PawAccountWdigestCredentials.ps1)

```powershell
# Configure-PawAccountWdigestCredentials.ps1
Write-Host "Disabling WDigest plaintext credential caching on PAWs..." -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) { New-Item -Path $WDigestPath -Force | Out-Null }
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force

Write-Host "WDigest credential caching disabled." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountWdigestCredentialsStatus.ps1](../audit_scripts/Get-PawAccountWdigestCredentialsStatus.ps1)

```powershell
# Get-PawAccountWdigestCredentialsStatus.ps1
Write-Host "--- Auditing PAW WDigest Credential Caching ---" -ForegroundColor Cyan

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
