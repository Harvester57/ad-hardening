# [REQ-PAW-193] Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Search
* **Policy Settings**:
  * Allow Cortana
  * Allow Cortana above lock screen
  * Allow indexing of encrypted files
  * Allow search and Cortana to use location
* **Supported On**: Windows 10 (Version 1511) or Windows Server 2016 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search`
* **Registry Values**:
  * `AllowCortana` = `0` (REG_DWORD, Suppress Cortana voice assistance)
  * `AllowCortanaAboveLock` = `0` (REG_DWORD, Block Cortana execution when device is locked)
  * `AllowIndexingEncryptedStoresOrItems` = `0` (REG_DWORD, Prevent indexing of EFS/encrypted files)
  * `AllowSearchToUseLocation` = `0` (REG_DWORD, Block search features from accessing device location)
* **Vulnerability References**: MITRE ATT&CK: T1005 (Data from Local System), T1083 (File and Directory Discovery), T1056 (Input Capture), T1200 (Hardware Additions / Physical Access), T1020 (Automated Exfiltration)

---

## Rationale

Privileged Access Workstations (PAWs) are dedicated exclusively to Tier 0 Active Directory and core infrastructure administration. Because administrative consoles are used to generate disaster-recovery scripts, inspect Active Directory objects, and manage domain secrets, the operating system search subsystem must be strictly constrained against cryptographic degradation and side-channel leakage.

### Technical Threat Vectors & PAW Security Exposure
1. **Cryptographic Protection Bypass via Search Indexing**: PAW operators frequently handle sensitive, locally encrypted files (such as emergency break-glass procedures, offline key backups, and sensitive audit manifests). If the search indexer (`SearchIndexer.exe`) processes encrypted stores, it decrypts file content and writes plain-text indexes into `Windows.edb` (`C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`). Any process with read access to the database or offline disk access can recover decrypted administrative plaintext, subverting file-level encryption controls.
2. **Physical Lock Screen Bypass via Voice Assistants**: When voice assistance is enabled above the lock screen, an adversary with temporary physical proximity to a locked PAW can execute voice commands. This permits unauthorized inspection of administrative notifications, active tasks, and system parameters without authenticating via smart card or multi-factor authentication.
3. **Ambient Audio Capture & Egress Traffic**: Voice recognition features continuously monitor the workstation microphone for trigger words and transmit voice telemetry to cloud speech processing services. In secure administrative operations centers or server rooms, ambient voice transmission presents an intolerable eavesdropping and compliance risk.
4. **Geolocation Tracking**: Permitting search services to track location leaks the physical facilities and network points of presence where Tier 0 administrative operations take place.

Disabling Cortana, suppressing above-lock interactions, disabling location access, and prohibiting the indexing of encrypted files guarantees that the PAW search engine operates strictly as a local, secure text query service.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Cortana voice interaction is completely disabled on PAWs. Encrypted files (EFS) will not be indexed in rapid full-text search results, requiring explicit navigation via File Explorer or PowerShell. Core administrative search capabilities (searching for installed MMC tools, PowerShell cmdlets, and local configuration files) operate with full responsiveness.
* **User Experience**: The search interface operates in an austere, local-only mode without voice prompts or web search suggestions.
* **Cryptographic Integrity**: Guarantees that encrypted administrative files cannot have their plaintext contents cached in the shared search database.
* **Rollout Recommendations**: Mandatory for all PAW deployment baselines; zero risk to administrative workflows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\Windows Components\Search
   ```
4. Configure the following policies:
   * **Allow Cortana**: Set to `Disabled`
   * **Allow Cortana above lock screen**: Set to `Disabled`
   * **Allow indexing of encrypted files**: Set to `Disabled`
   * **Allow search and Cortana to use location**: Set to `Disabled`
5. Click **Apply**, then click **OK** for each policy.
6. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtSearchCortanaRestrictions.ps1](../implementation_scripts/Configure-PawAtSearchCortanaRestrictions.ps1)

```powershell
#Configure-PawAtSearchCortanaRestrictions.ps1
# Description: Configures Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs.

Write-Host "Configuring Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtSearchCortanaRestrictionsStatus.ps1](../audit_scripts/Get-PawAtSearchCortanaRestrictionsStatus.ps1)

```powershell
#Get-PawAtSearchCortanaRestrictionsStatus.ps1
# Description: Audits Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs.

Write-Host "--- Auditing Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$ValueName = "AllowCortana"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$ValueName = "AllowCortanaAboveLock"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$ValueName = "AllowIndexingEncryptedStoresOrItems"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$ValueName = "AllowSearchToUseLocation"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

### Option C: Manual Verification

Verify the applied policy settings via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /s
```
Expected output:
```text
AllowCortana                          REG_DWORD    0x0
AllowCortanaAboveLock                 REG_DWORD    0x0
AllowIndexingEncryptedStoresOrItems   REG_DWORD    0x0
AllowSearchToUseLocation              REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Sections 18.10.59.3, 18.10.59.4, 18.10.59.5, 18.10.59.6
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Windows Search
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/), [T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083/), [T1056: Input Capture](https://attack.mitre.org/techniques/T1056/), [T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200/), [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
* **Related Controls**: [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md), [REQ-PAW-177: Administrative Templates: Interactive Logon and Credential Display Options for PAWs](configure-paw-at-logon-display-options.md)
