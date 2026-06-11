# Hardening Requirement: Harden TLS Protocols, Cipher Suites, and Elliptic Curves

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, PAWs, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Protocols**: `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`
  * **Cipher Suite Order**: `Computer Configuration\Administrative Templates\Network\SSL Configuration Settings` -> **SSL Cipher Suite Order** (Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` -> `Functions`)
  * **ECC Curve Order**: `Computer Configuration\Administrative Templates\Network\SSL Configuration Settings` -> **ECC Curve Order** (Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` -> `EccCurves`)

---

## Rationale
Legacy versions of SSL (2.0 and 3.0) and TLS (1.0 and 1.1) are cryptographically weak and vulnerable to various attacks (such as BEAST, POODLE, and SWEET32) that can lead to credential exposure and session hijacking. Domain services, including LDAPS and WinRM, must enforce the usage of TLS 1.2 and TLS 1.3 (where supported) to prevent protocol downgrade attacks.

In addition to disabling insecure protocol versions, the TLS cipher suites and Elliptic Curves must be restricted to modern, collision-resistant options. CBC (Cipher Block Chaining) mode and RC4 ciphers are prone to padding oracle attacks. Restricting configurations to AES-GCM (Galois/Counter Mode) authenticated encryption suites combined with strong Elliptic Curve Diffie-Hellman (ECDHE) curves (such as Curve25519 and NIST P-384) guarantees confidentiality, integrity, and perfect forward secrecy (PFS).

---

## Legacy Impact & Compatibility
* **Legacy Clients**: Operating systems prior to Windows 7/Server 2008 R2 (without updates enabling TLS 1.2) or outdated third-party management agents, appliances, and legacy printers will fail to establish secure connections (LDAPS, HTTPS, RDP, WinRM) with hardened hosts.
* **Domain Controller Reachability**: Active Directory replication between DCs remains unaffected as it relies on RPC (Kerberos) rather than TLS. However, client-facing services such as secure LDAP (LDAPS) require TLS; clients must support TLS 1.2.
* **Administrative Access**: Admin connections (such as WinRM over HTTPS or RDP) will require TLS 1.2. Administrative machines (PAWs) must be configured to support the same cipher suites.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Enforce SSL Cipher Suite Order and ECC Curve Order via GPO
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting all domain assets (e.g., `GPO_Hardening_TLS_Schannel`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Network\SSL Configuration Settings`
4. Double-click the **SSL Cipher Suite Order** policy:
   * Set the policy to **Enabled**.
   * In the **SSL Cipher Suites** text box, enter the hardened comma-separated cipher suite string:
     `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`
5. Double-click the **ECC Curve Order** policy:
   * Set the policy to **Enabled**.
   * In the **ECC Curves** text box, enter the curves in order of preference:
     `curve25519,nistP384,nistP256`
6. Click **OK**.

#### 2. Deploy Schannel Protocol Registry settings via GPO Preferences
Since Schannel protocol versions (disabling TLS 1.0/1.1 and enabling TLS 1.2/1.3) are not exposed via default ADMX templates, configure them using **Registry Preferences**:
1. Within the same GPO, navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
2. Right-click **Registry**, select **New** -> **Registry Item**.
3. Create registry values under:
   `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`
4. Configure key pairs for each protocol (`SSL 2.0`, `SSL 3.0`, `TLS 1.0`, `TLS 1.1`, `TLS 1.2`, `TLS 1.3`) under both `Client` and `Server` subkeys:
   * **To Disable (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)**:
     * Value Name: `Enabled` | Type: `REG_DWORD` | Value Data: `0`
     * Value Name: `DisabledByDefault` | Type: `REG_DWORD` | Value Data: `1`
   * **To Enable (TLS 1.2, TLS 1.3)**:
     * Value Name: `Enabled` | Type: `REG_DWORD` | Value Data: `1`
     * Value Name: `DisabledByDefault` | Type: `REG_DWORD` | Value Data: `0`

*Note: Systems must be rebooted for Schannel protocol and cipher settings to take effect.*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally on testing hosts or non-GPO-managed systems.

#### Remediation Script:
```powershell
# Set-TLSConfiguration.ps1
# Description: Hardens TLS/Schannel protocols, prioritizes modern cipher suites, and orders ECC curves.

Write-Host "Configuring Schannel protocols, cipher suites, and ECC curves..." -ForegroundColor Cyan

# Define Protocols to disable
$ProtocolsToDisable = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
# Define Protocols to enable
$ProtocolsToEnable = @("TLS 1.2", "TLS 1.3")

# 1. Configure Protocols
$SchannelRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

foreach ($Proto in $ProtocolsToDisable) {
    $Subkeys = @("Client", "Server")
    foreach ($Subkey in $Subkeys) {
        $Path = "$($SchannelRoot)\$($Proto)\$($Subkey)"
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name "Enabled" -Value 0 -Type DWord -Force | Out-Null
        Set-ItemProperty -Path $Path -Name "DisabledByDefault" -Value 1 -Type DWord -Force | Out-Null
    }
}

foreach ($Proto in $ProtocolsToEnable) {
    $Subkeys = @("Client", "Server")
    foreach ($Subkey in $Subkeys) {
        $Path = "$($SchannelRoot)\$($Proto)\$($Subkey)"
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name "Enabled" -Value 1 -Type DWord -Force | Out-Null
        Set-ItemProperty -Path $Path -Name "DisabledByDefault" -Value 0 -Type DWord -Force | Out-Null
    }
}

# 2. Configure SSL Cipher Suite Order and ECC Curve Order Policy
$SSLConfigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (-not (Test-Path $SSLConfigPath)) {
    New-Item -Path $SSLConfigPath -Force | Out-Null
}

# Define cipher suites list
$CipherSuites = @(
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
)

# Define ECC curves list
$EccCurves = @(
    "curve25519",
    "nistP384",
    "nistP256"
)

# Apply policy properties
Set-ItemProperty -Path $SSLConfigPath -Name "Functions" -Value $CipherSuites -Type MultiString -Force | Out-Null
Set-ItemProperty -Path $SSLConfigPath -Name "EccCurves" -Value $EccCurves -Type MultiString -Force | Out-Null

Write-Host "Schannel configuration applied. A system reboot is required to apply changes." -ForegroundColor Green
```

#### Audit Script:
```powershell
# Test-TLSConfiguration.ps1
# Description: Audits TLS/Schannel protocol configuration, cipher suites, and ECC curves.

Write-Host "Auditing TLS and Cryptographic configurations..." -ForegroundColor Cyan

$NonCompliantCount = 0
$SchannelRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# 1. Audit Protocols
$ProtocolsToDisable = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($Proto in $ProtocolsToDisable) {
    $Subkeys = @("Client", "Server")
    foreach ($Subkey in $Subkeys) {
        $Path = "$($SchannelRoot)\$($Proto)\$($Subkey)"
        if (Test-Path $Path) {
            $Enabled = Get-ItemPropertyValue -Path $Path -Name "Enabled" -ErrorAction SilentlyContinue
            if ($Enabled -ne 0) {
                Write-Host "    - Protocol $($Proto) ($($Subkey)) is not disabled (Non-Compliant)." -ForegroundColor Red
                $NonCompliantCount++
            } else {
                Write-Host "    - Protocol $($Proto) ($($Subkey)) is disabled (Compliant)." -ForegroundColor Green
            }
        } else {
            Write-Host "    - Protocol $($Proto) ($($Subkey)) registry key does not exist (Compliant)." -ForegroundColor Green
        }
    }
}

# 2. Audit SSL Policy and ECC Curves
$SSLConfigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (Test-Path $SSLConfigPath) {
    $Functions = Get-ItemPropertyValue -Path $SSLConfigPath -Name "Functions" -ErrorAction SilentlyContinue
    $EccCurves = Get-ItemPropertyValue -Path $SSLConfigPath -Name "EccCurves" -ErrorAction SilentlyContinue

    if ($null -eq $Functions -or $Functions.Length -eq 0) {
        Write-Host "    - SSL Cipher Suite order policy is not configured (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        if ($Functions[0] -match "GCM") {
            Write-Host "    - SSL Cipher Suite priority matches standards (Compliant)." -ForegroundColor Green
        } else {
            Write-Host "    - SSL Cipher Suite priority does not favor secure GCM suites first (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        }
    }

    if ($null -eq $EccCurves -or $EccCurves.Length -eq 0) {
        Write-Host "    - ECC Curve priority policy is not configured (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        if ($EccCurves[0] -eq "curve25519" -or $EccCurves[0] -eq "nistP384") {
            Write-Host "    - ECC Curve priority matches standards (Compliant)." -ForegroundColor Green
        } else {
            Write-Host "    - ECC Curve priority does not favor curve25519/nistP384 (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        }
    }
} else {
    Write-Host "    - Custom SSL configuration policies are not configured (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
}

if ($NonCompliantCount -eq 0) {
    Write-Host "TLS and Cryptographic configuration: Compliant." -ForegroundColor Green
} else {
    Write-Host "TLS and Cryptographic configuration: Non-Compliant ($($NonCompliantCount) issue(s) detected)." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R18 (Schannel configuration)
* **ANSSI General Security Rules (RGS)**: Annex B1 (Cryptographic mechanisms)
* **CIS Windows Server 2016 Benchmark**: Section 18.10 (SSL Configuration Settings)
* **Microsoft Security Guidance**: Transport Layer Security (TLS) best practices
