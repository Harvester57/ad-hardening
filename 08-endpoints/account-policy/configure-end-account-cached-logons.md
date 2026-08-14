# [REQ-END-167] Account Policy: Cached Logons and PBKDF2 Iteration Count for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Number of previous logons to cache`
  * **GPO Path**: `Computer Configuration\Preferences\Windows Settings\Registry` (for `NL$IterationCount`)
  * **Registry Locations**:
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount` = `0` (REG_DWORD)
    * `HKLM\SECURITY\Cache\NL$IterationCount` = `1954` (REG_DWORD, 1954 = 2,000,896 rounds of PBKDF2-SHA1)

---

## Rationale
Windows caches previous domain credentials locally as MSCacheV2 / DCC2 hashes derived via PBKDF2-SHA1 to allow offline validation.
* **Cached Logons Count (0)**: Setting `CachedLogonsCount` to `0` prevents local storage of credential hashes on standard domain endpoints, forcing logon validation directly against a Domain Controller and ensuring dumped SAM/SECURITY databases yield no cached credentials.
* **PBKDF2 Iteration Count (1954)**: For portable endpoints (e.g., laptops) where caching must be enabled for offline work, setting `NL$IterationCount` to `1954` increases derivation rounds to 2,000,896 iterations, drastically increasing resistance to offline GPU-accelerated brute-force attacks.

---

## Legacy Impact & Compatibility
* **Offline Logon**: When cached logons are disabled (`0`), endpoints must have active network connectivity (or pre-boot VPN) to a Domain Controller to process user logins.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Set **Interactive logon: Number of previous logons to cache (in case domain controller is not available)** to **0**.
5. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
6. Right-click **Registry**, select **New** -> **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SECURITY\Cache`
   * **Value name**: `NL$IterationCount`
   * **Value type**: `REG_DWORD`
   * **Value data**: `1954` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountCachedLogons.ps1](../implementation_scripts/Configure-EndAccountCachedLogons.ps1)

```powershell
# Configure-EndAccountCachedLogons.ps1
Write-Host "Configuring Endpoint cached logon restrictions and PBKDF2 iterations..." -ForegroundColor Cyan

# 1. Disable cached logons count
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -Value 0 -Type DWord -Force

# 2. Configure PBKDF2 Iteration Count
$CachePath = "HKLM:\SECURITY\Cache"
if (-not (Test-Path $CachePath)) { New-Item -Path $CachePath -Force | Out-Null }
Set-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -Value 1954 -Type DWord -Force

Write-Host "Cached logons count disabled and PBKDF2 iteration count configured." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountCachedLogonsStatus.ps1](../audit_scripts/Get-EndAccountCachedLogonsStatus.ps1)

```powershell
# Get-EndAccountCachedLogonsStatus.ps1
Write-Host "--- Auditing Endpoint Cached Logons and PBKDF2 Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit CachedLogonsCount
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$CacheCount = (Get-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -ErrorAction SilentlyContinue).CachedLogonsCount
if ($CacheCount -ne 0) {
    Write-Host "    [!] VULNERABLE: CachedLogonsCount is '$CacheCount' (Expected: 0)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] CachedLogonsCount: 0" -ForegroundColor Green
}

# 2. Audit NL$IterationCount
$CachePath = "HKLM:\SECURITY\Cache"
$IterCount = (Get-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -ErrorAction SilentlyContinue)."NL`$IterationCount"
if ($IterCount -ne 1954) {
    Write-Host "    [!] VULNERABLE: NL`$IterationCount is '$IterCount' (Expected: 1954)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] NL`$IterationCount: 1954" -ForegroundColor Green
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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.9.4 (Interactive logon: Number of previous logons to cache)
* **ANSSI AD Hardening Guide**: Recommendations on credential caching and local password protection
* **DoD Windows 11 Computer STIG v2r6**: Cached domain logon restrictions
