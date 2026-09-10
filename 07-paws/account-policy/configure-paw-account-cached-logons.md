# [REQ-PAW-156] Account Policy: Cached Logons and PBKDF2 Iteration Count for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Interactive logon: Number of previous logons to cache (in case domain controller is not available): `0` logons
  * Registry Preference: `HKLM\SECURITY\Cache\NL$IterationCount` = `1954`
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Keys & Values**:
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount` = `0` (REG_DWORD, Zero cached domain credentials stored)
  * `HKLM\SECURITY\Cache\NL$IterationCount` = `1954` (REG_DWORD, 1954 corresponds to ~2,001,920 PBKDF2-HMAC-SHA1 iterations)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1003.005: OS Credential Dumping: Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/), [T1003.002: OS Credential Dumping: Security Account Manager](https://attack.mitre.org/techniques/T1003/002/), [T1110.002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/), [T1078.002: Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

---

## Rationale

By default, Windows caches authentication verifiers for previously logged-on domain accounts to permit user authentication when an Active Directory Domain Controller cannot be reached. On Privileged Access Workstations, this feature poses an existential risk to Tier 0 directory security:

### Technical Threat Vectors and Defense Mechanics
1. **Domain Cached Credentials (DCC2 / MSCacheV2) Architecture**:
   When a user logs on to a domain member, the Local Security Authority Subsystem Service (LSASS) computes a credential verifier known as MSCacheV2 / DCC2. This verifier is derived from the user's NTLM hash and lowercase username using PBKDF2-HMAC-SHA1. The resulting hash entries (`NL$1`, `NL$2`, etc.) are written directly into the local `HKLM\SECURITY\Cache` registry subkey.
2. **Preventing Offline Credential Extraction (`CachedLogonsCount = 0`)**:
   If an adversary gains local administrator or SYSTEM privileges on a workstation, or acquires an offline disk image (e.g., via stolen physical media or hypervisor snapshots), they can extract the `SECURITY` and `SYSTEM` registry hives using tools like Mimikatz (`lsadump::cache`) or Impacket (`secretsdump.py`). Setting `CachedLogonsCount = 0` completely disables the credential caching engine in Winlogon: no credential verifiers are ever committed to disk, ensuring that physical or offline forensic theft yields zero cached administrative passwords.
3. **PBKDF2 Iteration Fortification (`NL$IterationCount = 1954`)**:
   In standard Windows configurations, the iteration count for DCC2 derivation defaults to 10,240 rounds. Modern GPU clusters (utilizing tools like Hashcat with mode 2100) can test hundreds of millions of password guesses per second against 10,240-round hashes. The Windows Netlogon cache formula derives total iteration rounds as `(NL$IterationCount + 1) * 1024`. Setting `NL$IterationCount = 1954` produces `(1954 + 1) * 1024 = 2,001,920` iterations—a ~200-fold computational increase. Even in recovery scenarios where a cache entry could temporarily be initialized, offline cracking is rendered computationally intractable.
4. **Tier 0 PAW Isolation Posture**:
   PAWs are dedicated exclusively to Tier 0 directory administration and operate strictly within protected administrative management VLANs with uninterrupted, direct connectivity to Tier 0 Domain Controllers. PAWs must never be taken on travel, connected to public networks, or operated in a disconnected offline state. Enforcing `CachedLogonsCount = 0` guarantees that every administrative logon is validated live against the directory, upholding centralized account revocation and smart card PIN verification.

---

## Legacy Impact & Compatibility

* **Offline Logon Inability**: Administrators cannot log on to a PAW unless the device has an active, live network connection to an authorized Active Directory Domain Controller. Attempting to log on while disconnected will immediately produce an error stating that no domain controllers are available.
* **Network Redundancy Requirement**: Administrative subnets housing PAWs must possess redundant network paths and resilient DNS resolution to Domain Controllers to prevent administrative lockouts during maintenance windows.
* **Registry Access Control**: Modifying `HKLM\SECURITY\Cache` requires SYSTEM-level privileges. GPO Preferences or administrative deployment scripts must execute within the computer/SYSTEM security context.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Double-click **Interactive logon: Number of previous logons to cache (in case domain controller is not available)**.
5. Check **Define this policy setting** and set the cache value to **0** logons.
6. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
7. Right-click **Registry**, select **New** -> **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SECURITY\Cache`
   * **Value name**: `NL$IterationCount`
   * **Value type**: `REG_DWORD`
   * **Value data**: `1954` (Decimal)
8. Link the GPO to the dedicated PAW OU and verify application using `gpresult /r`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountCachedLogons.ps1](../implementation_scripts/Configure-PawAccountCachedLogons.ps1)

```powershell
# Configure-PawAccountCachedLogons.ps1
# Description: Disables cached domain logons and fortifies PBKDF2 iteration count on PAWs.

Write-Host "Configuring PAW cached logon restrictions and PBKDF2 iterations..." -ForegroundColor Cyan

# 1. Disable cached logons count
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path -Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -Value 0 -Type DWord -Force

# 2. Configure PBKDF2 Iteration Count
$CachePath = "HKLM:\SECURITY\Cache"
if (-not (Test-Path -Path $CachePath)) {
    New-Item -Path $CachePath -Force | Out-Null
}
Set-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -Value 1954 -Type DWord -Force

Write-Host "Cached logons count disabled (0) and PBKDF2 iteration count configured (1954)." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountCachedLogonsStatus.ps1](../audit_scripts/Get-PawAccountCachedLogonsStatus.ps1)

```powershell
# Get-PawAccountCachedLogonsStatus.ps1
# Description: Audits cached logons count and PBKDF2 iteration count on PAWs.

Write-Host "--- Auditing PAW Cached Logons and PBKDF2 Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit CachedLogonsCount
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path -Path $WinlogonPath)) {
    Write-Host "    [!] MISSING KEY: $WinlogonPath" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    $CacheCount = (Get-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -ErrorAction SilentlyContinue).CachedLogonsCount
    if ($CacheCount -ne 0) {
        Write-Host "    [!] VULNERABLE: CachedLogonsCount is '$CacheCount' (Expected: 0)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] CachedLogonsCount: 0 (Secure - Cache Disabled)" -ForegroundColor Green
    }
}

# 2. Audit NL$IterationCount
$CachePath = "HKLM:\SECURITY\Cache"
if (-not (Test-Path -Path $CachePath)) {
    Write-Host "    [!] MISSING KEY: $CachePath" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    $IterCount = (Get-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -ErrorAction SilentlyContinue)."NL`$IterationCount"
    if ($IterCount -ne 1954) {
        Write-Host "    [!] VULNERABLE: NL`$IterationCount is '$IterCount' (Expected: 1954)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] NL`$IterationCount: 1954 (Secure - ~2M PBKDF2 Iterations)" -ForegroundColor Green
    }
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

### Option C: Manual Verification

Verify the applied settings using administrative command line queries:
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount
```
Confirm that `CachedLogonsCount` returns `0x0`.

To inspect the `SECURITY\Cache` key (requires elevated privileges via `psexec -s cmd.exe` or SYSTEM context):
```cmd
reg query "HKLM\SECURITY\Cache" /v NL$IterationCount
```
Confirm that `NL$IterationCount` returns `0x7a2` (Decimal `1954`).

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.9.4 (Ensure 'Interactive logon: Number of previous logons to cache' is set to '0' logons)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.9.4 (Ensure 'Interactive logon: Number of previous logons to cache' is set to '0' logons)
* **DoD Windows 11 Computer STIG**: Rule SV-220721r879621_rule (Setting cached domain logons to 0)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (PAW Isolation and Elimination of Local Credential Caching)
* **MITRE ATT&CK**: [T1003.005: Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/)
* **Related Controls**: [REQ-END-167: Account Policy: Cached Logons and PBKDF2 Iteration Count for Endpoints](../../08-endpoints/account-policy/configure-end-account-cached-logons.md), [REQ-PAW-152: Account Policy: Password Policy for PAWs](configure-paw-account-password-policy.md)
