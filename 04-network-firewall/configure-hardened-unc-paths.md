# Hardening Requirement: Configure Hardened UNC Paths and LDAP Client Signing

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Hardened UNC Paths (GPO)**: `Computer Configuration\Policies\Administrative Templates\Network\Network Provider\Hardened UNC Paths` -> Enabled
    * Path: `\\*\NETLOGON` | Value: `RequireIntegrity=1,RequireMutualAuthentication=1`
    * Path: `\\*\SYSVOL` | Value: `RequireIntegrity=1,RequireMutualAuthentication=1`
  * **Insecure Guest Logons (GPO)**: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Enable insecure guest logons` -> Disabled
  * **LDAP Client Signing (GPO)**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LDAP client signing requirements` -> Negotiate signing
  * **Registry Location (UNC Paths)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths`
  * **Registry Location (Guest Logons)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation` -> `AllowInsecureGuestAuth` = `0` (REG_DWORD)
  * **Registry Location (LDAP Client)**: `HKLM\System\CurrentControlSet\Services\LDAP` -> `LDAPClientIntegrity` = `1` (REG_DWORD)

---

## Rationale
Active Directory clients and servers routinely query Domain Controllers to retrieve Group Policy Objects (GPOs), startup/shutdown scripts, and user logon scripts from the `SYSVOL` and `NETLOGON` shares. By default, these connections are made over standard UNC paths and do not strictly enforce integrity validation (SMB signing) or mutual authentication.

Enforcing these channel-level controls mitigates the following threat vectors:
1. **GPO Spoofing and Execution Tampering**: An attacker positioned on the local network using man-in-the-middle (MitM) techniques (such as ARP spoofing or DNS poisoning) can intercept GPO retrieval traffic. Without Hardened UNC Paths, the attacker can spoof the Domain Controller and inject a malicious GPO or a modified script, which then executes with local SYSTEM privileges on the client host. Enforcing integrity and mutual authentication on `SYSVOL` and `NETLOGON` blocks this spoofing vector.
2. **Insecure Guest Logons**: Disabling insecure guest logons stops the workstation or server from automatically authenticating to untrusted remote SMB shares using guest credentials. This prevents attackers from setting up rogue SMB servers that trick hosts into leaking NetNTLM credentials or executing untrusted files.
3. **LDAP Session Hijacking**: Forcing outgoing LDAP client connections to negotiate signing protects directory queries made by Member Servers or Domain Controllers (acting as clients) from interception, packet tampering, or sniffing.

---

## Legacy Impact & Compatibility
* **Legacy Client Access**: Non-domain-joined systems or legacy operating systems (prior to Windows Vista/Server 2008) that cannot perform Kerberos mutual authentication will fail to access the `SYSVOL` or `NETLOGON` shares on Domain Controllers.
* **Third-party SMB Implementation Compatibility**: Virtual machines or network storage devices that access SYSVOL for GPO processing must support SMB v2/v3 with signing.
* **LDAP Client Queries**: Legacy third-party applications running on member servers that query AD directories over unencrypted LDAP (TCP port 389) without supporting signing negotiations will fail. These applications must be configured to utilize LDAPS (TCP port 636) or enable signing negotiation support.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Configure Hardened UNC Paths
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to all target computers (e.g., `GPO_Computer_Hardening_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Network\Network Provider`
4. Double-click **Hardened UNC Paths**.
5. Set it to **Enabled**.
6. Click **Show...** in the options panel, and add the following entries:
   * **Value name**: `\\*\NETLOGON` | **Value**: `RequireIntegrity=1,RequireMutualAuthentication=1`
   * **Value name**: `\\*\SYSVOL` | **Value**: `RequireIntegrity=1,RequireMutualAuthentication=1`
7. Click **OK**.

#### 2. Disable Insecure Guest Logons
1. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation`
2. Double-click **Enable insecure guest logons**.
3. Set it to **Disabled** and click **OK**.

#### 3. Enforce LDAP Client Signing
1. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Double-click **Network security: LDAP client signing requirements**.
3. Set it to **Negotiate signing** and click **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply the hardened network provider, Lanman Workstation, and LDAP client configurations.

[Download Script: Set-HardenedUNCAndClientSigning.ps1](implementation_scripts/Set-HardenedUNCAndClientSigning.ps1)

```powershell
# Set-HardenedUNCAndClientSigning.ps1
# Description: Configures Hardened UNC Paths for SYSVOL/NETLOGON, disables insecure guest logons, and enforces LDAP client signing.

Write-Host "Applying network provider and client channel hardening..." -ForegroundColor Cyan

# 1. Hardened UNC Paths configuration
$UNCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
if (-not (Test-Path $UNCPath)) {
    New-Item -Path $UNCPath -Force | Out-Null
}
Set-ItemProperty -Path $UNCPath -Name "\\*\NETLOGON" -Value "RequireIntegrity=1,RequireMutualAuthentication=1" -Type String -ErrorAction Stop
Set-ItemProperty -Path $UNCPath -Name "\\*\SYSVOL" -Value "RequireIntegrity=1,RequireMutualAuthentication=1" -Type String -ErrorAction Stop
Write-Host "[+] Hardened UNC Paths for NETLOGON and SYSVOL configured." -ForegroundColor Green

# 2. Disable Insecure Guest Logons
$LanmanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if (-not (Test-Path $LanmanPath)) {
    New-Item -Path $LanmanPath -Force | Out-Null
}
Set-ItemProperty -Path $LanmanPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Insecure guest logons disabled." -ForegroundColor Green

# 3. Enforce LDAP Client Signing Requirements
$LdapPath = "HKLM:\System\CurrentControlSet\Services\LDAP"
if (-not (Test-Path $LdapPath)) {
    New-Item -Path $LdapPath -Force | Out-Null
}
Set-ItemProperty -Path $LdapPath -Name "LDAPClientIntegrity" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] LDAP Client signing requirement set to Negotiate signing." -ForegroundColor Green
```

*To audit the network provider, Lanman workstation, and LDAP client signing configurations:*
[Download Script: Get-HardenedUNCAndClientSigningStatus.ps1](audit_scripts/Get-HardenedUNCAndClientSigningStatus.ps1)

```powershell
# Get-HardenedUNCAndClientSigningStatus.ps1
# Description: Audits the registry configuration of Hardened UNC Paths, Lanman guest authentication, and LDAP Client signing.

Write-Host "--- Auditing Hardened UNC Paths and Client Signing status ---" -ForegroundColor Cyan

# 1. Audit UNC Paths
$UNCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
if (Test-Path $UNCPath) {
    $NetlogonVal = Get-ItemProperty -Path $UNCPath -Name "\\*\NETLOGON" -ErrorAction SilentlyContinue
    $SysvolVal = Get-ItemProperty -Path $UNCPath -Name "\\*\SYSVOL" -ErrorAction SilentlyContinue
    
    $NetColor = if ($NetlogonVal -and $NetlogonVal.'\\*\NETLOGON' -eq "RequireIntegrity=1,RequireMutualAuthentication=1") { "Green" } else { "Red" }
    $SysColor = if ($SysvolVal -and $SysvolVal.'\\*\SYSVOL' -eq "RequireIntegrity=1,RequireMutualAuthentication=1") { "Green" } else { "Red" }
    
    Write-Host "    - Hardened UNC NETLOGON: $($NetlogonVal.'\\*\NETLOGON') (Expected: RequireIntegrity=1,RequireMutualAuthentication=1)" -ForegroundColor $NetColor
    Write-Host "    - Hardened UNC SYSVOL:   $($SysvolVal.'\\*\SYSVOL') (Expected: RequireIntegrity=1,RequireMutualAuthentication=1)" -ForegroundColor $SysColor
} else {
    Write-Host "    - Hardened UNC registry path: NOT FOUND" -ForegroundColor Red
}

# 2. Audit Guest Logons
$LanmanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$GuestVal = Get-ItemProperty -Path $LanmanPath -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
$GuestSetting = if ($GuestVal) { $GuestVal.AllowInsecureGuestAuth } else { 1 }
$GuestColor = if ($GuestSetting -eq 0) { "Green" } else { "Red" }
Write-Host "    - Allow Insecure Guest Logons: $GuestSetting (Expected: 0)" -ForegroundColor $GuestColor

# 3. Audit LDAP Client Signing
$LdapPath = "HKLM:\System\CurrentControlSet\Services\LDAP"
$LdapVal = Get-ItemProperty -Path $LdapPath -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue
$LdapSetting = if ($LdapVal) { $LdapVal.LDAPClientIntegrity } else { 0 }
$LdapColor = if ($LdapSetting -eq 1) { "Green" } else { "Red" }
Write-Host "    - LDAP Client Integrity (Signing): $LdapSetting (Expected: 1 - Negotiate)" -ForegroundColor $LdapColor
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R19 (Configuration des Hardened UNC Paths pour SYSVOL et NETLOGON)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.2.1 (Lanman Workstation), Section 18.1.1 (Network Provider)
* **Microsoft Security Baseline Focus**: Windows Server and Client Group Policy Security Baselines
