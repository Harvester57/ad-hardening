# [REQ-END-204] Administrative Templates: Windows Search and Cortana Privacy Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
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

The Windows Search and Cortana infrastructure provides desktop indexing, voice recognition, and location-aware query capabilities. In enterprise environments, unconstrained search and voice assistant features introduce severe data leakage, physical authentication bypass, and cryptographic exposure risks.

### Technical Threat Vectors & Cryptographic Vulnerabilities
1. **Cryptographic Bypass via Encrypted File Indexing**: The Encrypting File System (EFS) protects sensitive files using per-user public key certificates and symmetric file encryption keys (FEK). When the Windows Search indexer (`SearchIndexer.exe`) is allowed to index encrypted stores, it decrypts file contents using the active user's credentials and writes plain-text content, tokens, and metadata into the centralized search database (`C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`). Because `Windows.edb` is a shared database with separate access controls, an attacker gaining local administrative privileges or exploiting local service vulnerabilities can extract plaintext strings and sensitive documents directly from the database, completely bypassing file-level EFS encryption.
2. **Above-Lock Physical Authentication Bypass**: When Cortana is permitted to operate above the lock screen, physical passersby or unauthenticated attackers in physical proximity to a locked workstation can issue voice queries. This allows unauthorized actors to inspect user calendar appointments, read message previews, query contact lists, and potentially execute authorized voice commands without providing PIN, password, or biometric authentication.
3. **Voice Audio Ingestion & Telemetry Transmission**: Active voice assistants maintain continuous ambient audio listening queues to detect wake words ("Hey Cortana"). Detected speech samples, query strings, and environmental audio telemetry are transmitted to Microsoft Bing cloud endpoints for natural language processing, creating compliance and eavesdropping concerns in sensitive corporate offices.
4. **Endpoint Geolocation Disclosure**: Allowing the search subsystem to access device location services attaches Wi-Fi BSSID triangulation and GPS coordinates to telemetry logs and web search queries, disclosing the physical location of corporate mobile assets and remote personnel.

Enforcing these four policies eliminates voice-based interactions, ensures encrypted files remain strictly unindexed, and prevents unauthorized geolocation tracking.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Cortana voice interaction is completely disabled. Encrypted files (EFS) will not appear in rapid full-text search results; users must navigate to them directly via File Explorer. Standard local indexing of unencrypted corporate documents, emails in Outlook, and local file searches continue to function with full speed and fidelity.
* **User Experience**: Voice search prompts are removed. The search bar functions as a standard, local/text-only search interface.
* **Cryptographic Integrity**: EFS encrypted stores are guaranteed against plaintext leakage into `Windows.edb`.
* **Rollout Recommendations**: Completely safe to deploy across all enterprise endpoints; no negative impact on line-of-business software.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
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
6. Link the GPO to the target Organizational Unit (OU) and verify replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtSearchCortanaRestrictions.ps1](../implementation_scripts/Configure-EndAtSearchCortanaRestrictions.ps1)

```powershell
#Configure-EndAtSearchCortanaRestrictions.ps1
# Description: Configures Administrative Templates: Windows Search and Cortana Privacy Restrictions.

Write-Host "Configuring Administrative Templates: Windows Search and Cortana Privacy Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Search and Cortana Privacy Restrictions applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtSearchCortanaRestrictionsStatus.ps1](../audit_scripts/Get-EndAtSearchCortanaRestrictionsStatus.ps1)

```powershell
#Get-EndAtSearchCortanaRestrictionsStatus.ps1
# Description: Audits Administrative Templates: Windows Search and Cortana Privacy Restrictions.

Write-Host "--- Auditing Administrative Templates: Windows Search and Cortana Privacy Restrictions ---" -ForegroundColor Cyan
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
Ensure all four values are present and set to `0x0`:
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
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/), [T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083/), [T1056: Input Capture](https://attack.mitre.org/techniques/T1056/), [T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200/), [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
* **Related Controls**: [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md), [REQ-END-188: Administrative Templates: Interactive Logon and Credential Display Options](configure-end-at-logon-display-options.md)
