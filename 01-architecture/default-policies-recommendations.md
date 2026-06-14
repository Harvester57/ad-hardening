# [REQ-ARCH-005] Default Domain and Domain Controllers Policies Management

## Target Scope
* **Applicable Systems**: Domain Controllers and Domain Members (Forest-wide)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Default Domain Policy` (GUID: `{31B2F340-016D-11D2-945F-00C04FB984F9}`)
    * `Default Domain Controllers Policy` (GUID: `{6AC1786C-016F-11D2-945F-00C04fB984F9}`)
    * **EFS path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies\Encrypting File System`
    * **Background Refresh path**: `Computer Configuration\Policies\Administrative Templates\System\Group Policy`
  * **Registry Locations**:
    * **EFS**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS`
      * `EfsConfiguration` = `1` (REG_DWORD, 1 = Disabled)
    * **Background Refresh**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
      * `DisableBkGndGroupPolicy` = `0` (REG_DWORD, 0 = Active/Enabled)

---

## Rationale
Modifying the Default Domain Policy (DDP) and Default Domain Controllers Policy (DDCP) introduces significant operational risks. These default policies define the core directory baseline configurations required for Active Directory to initialize, replicate, and authenticate.

However, a critical exception to modular Group Policy design applies to **Account Policies** (Password, Account Lockout, and Kerberos settings) and **Encrypting File System (EFS)** policies. Windows operating systems only process domain-wide Account Policies from the GPO linked directly to the domain root (by default, the Default Domain Policy). Custom GPOs linked at lower levels containing these settings will be ignored for domain accounts. Therefore, these specific baselines must be configured directly within the Default Domain Policy itself.

All other custom hardening settings (such as local User Rights Assignments, Audit Policies, and registry parameters) should be managed via dedicated modular GPOs (e.g., `SEC_DomainControllers_Hardening`) linked at higher precedence.

Integrating the following controls inside the DDP/DDCP and custom GPOs completes the Active Directory management baseline:
1. **Disabling Encrypting File System (EFS)**: EFS allows users to encrypt files on local drives. This makes files difficult to recover or back up securely. Enterprise environments should enforce full-disk encryption (BitLocker) rather than user-managed file-level encryption. Disabling EFS prevents unauthorized user-level encryption.
2. **Enforcing Group Policy Background Refresh**: Ensuring that Group Policy background refresh is active prevents unauthorized local overrides from persisting. Setting the policy `Turn off background refresh of Group Policy` to **Disabled** ensures that GPOs are reapplied every 90 minutes.
3. **Mandating GPO Comments**: Documenting the purpose, author, and revision history in the GPO comments field ensures accountability and prevents configuration drift.
4. **Restricting gpupdate /force Overuse**: Running `gpupdate /force` causes endpoints and servers to re-download all applied GPOs from Domain Controllers. In large environments, this can trigger severe network congestion and CPU spikes on DCs. Administrators should use standard `gpupdate` without the `/force` switch unless a full re-application of unchanged policies is required.

---

## Legacy Impact & Compatibility
* **EFS Disabling**: Prior to disabling EFS, administrators must scan domain-joined machines for active EFS-encrypted files and decrypt them. If EFS is disabled while encrypted files exist, users will lose access to those files.
* **GPO Precedence**: The modular hardening GPOs must be linked at the root/OU with a lower link order number (higher precedence) than the default policies to ensure custom settings override defaults cleanly.

---

## Implementation Steps

### Option A: Group Policy Management Console (GPMC) (Preferred)

#### Step 1: Configure Default Domain Policy for Account and EFS Policies
1. Log on to a management workstation or Domain Controller with **Domain Admins** credentials.
2. Open the **Group Policy Management Console** (`gpmc.msc`).
3. Right-click the **Default Domain Policy** and select **Edit**.
4. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies`
5. Right-click **Encrypting File System** and select **Properties**.
6. In the **General** tab, under **File encryption using Encrypting File System (EFS)**, select **Disabled** and click **OK**.
7. Navigate to the Account Policies node to configure domain-wide Password and Lockout parameters as detailed in [configure-account-policies.md](../08-endpoints/configure-account-policies.md).

#### Step 2: Establish Modular GPOs for Non-Account Policies
1. In the `gpmc.msc` console tree, right-click **Group Policy Objects** and select **New**.
2. Name the GPO `SEC_DomainControllers_Hardening` (and `SEC_Domain_Hardening` for domain members) and click **OK**.
3. Right-click the **Domain Controllers** OU (or root domain) and select **Link an Existing GPO**.
4. Select `SEC_DomainControllers_Hardening` and click **OK**.
5. Select the **Domain Controllers** OU in the left pane, navigate to the **Linked Group Policy Objects** tab, select the custom hardening GPO, and use the green up arrow to set its **Link Order** to **1** (highest precedence).

#### Step 3: Configure Group Policy Background Refresh
1. Edit your modular hardening GPO (e.g., `SEC_DomainControllers_Hardening` or `SEC_Domain_Hardening`).
2. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Group Policy`
3. Double-click the policy **Turn off background refresh of Group Policy** and set it to **Disabled**.

#### Step 4: Mandate GPO Comments for Accountability
1. In GPMC, right-click your GPO, select **Properties**, and navigate to the **Comment** tab.
2. Enter a structured comment containing:
   * **Purpose**: [Brief explanation of GPO controls]
   * **Author**: [Administrator Name or Security Team]
   * **Date**: [Creation/Modification Date]
   * **Reference Requirement**: [e.g., REQ-ARCH-005]

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and set up the GPO structure, EFS, and background refresh locally.

#### 1. Local Audit (Audit-GPOPrecedence.ps1)

[Download Script: Audit-GPOPrecedence.ps1](audit_scripts/Audit-GPOPrecedence.ps1)

```powershell
# Audit-GPOPrecedence.ps1
# Description: Verifies GPO precedence on DC OU, and checks local EFS and background refresh registry configuration.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "--- Auditing Default Policies and Precedence ---" -ForegroundColor Cyan

# 1. Audit GPO Precedence on Domain Controllers OU
$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"

try {
    $OUInfo = Get-GPInheritance -Target $DCOUDN -ErrorAction Stop
    
    Write-Host "`nLinked GPOs on Domain Controllers OU:" -ForegroundColor Yellow
    $HardeningGPOFound = $false
    $HardeningOrder = 999
    $DefaultDCOrder = 999
    
    foreach ($link in $OUInfo.GpoLinks) {
        $status = if ($link.Enabled) { "Enabled" } else { "Disabled" }
        Write-Host "    - Link Order: $($link.Order) | GPO Name: $($link.DisplayName) | Status: $status" -ForegroundColor White
        
        if ($link.DisplayName -like "*Hardening*" -and $link.Enabled) {
            $HardeningGPOFound = $true
            $HardeningOrder = $link.Order
        }
        if ($link.DisplayName -eq "Default Domain Controllers Policy") {
            $DefaultDCOrder = $link.Order
        }
    }
    
    if ($HardeningGPOFound -and $HardeningOrder -lt $DefaultDCOrder) {
        Write-Host "`n[+] GPO Precedence: Compliant. Custom hardening GPO has higher precedence (Order $HardeningOrder) than Default DC Policy (Order $DefaultDCOrder)." -ForegroundColor Green
    } else {
        Write-Host "`n[!] VULNERABLE: No active dedicated hardening GPO found with higher precedence than Default DC Policy." -ForegroundColor Red
    }
} catch {
    Write-Host "[!] Could not retrieve GPO information for DC OU. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Audit EFS Registry status
$EfsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS"
$EfsVal = Get-ItemProperty -Path $EfsPath -Name "EfsConfiguration" -ErrorAction SilentlyContinue
if ($EfsVal -and $EfsVal.EfsConfiguration -eq 1) {
    Write-Host "[+] EFS Configuration: Secure (Disabled)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: EFS is not disabled in registry policies." -ForegroundColor Red
}

# 3. Audit Background Refresh status
$SysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$BkgVal = Get-ItemProperty -Path $SysPath -Name "DisableBkGndGroupPolicy" -ErrorAction SilentlyContinue
if ($BkgVal -and $BkgVal.DisableBkGndGroupPolicy -eq 0) {
    Write-Host "[+] Group Policy Background Refresh: Secure (Active)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Group Policy background refresh is turned off in registry." -ForegroundColor Red
}
```

#### 2. Local Remediation (Set-ADModularGPO.ps1)

[Download Script: Set-ADModularGPO.ps1](implementation_scripts/Set-ADModularGPO.ps1)

```powershell
# Set-ADModularGPO.ps1
# Description: Creates DC hardening GPO with top precedence, disables EFS, and enables background refresh locally.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "Applying Default Policies hardening baseline..." -ForegroundColor Cyan

# 1. Create and Link DC Hardening GPO
$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"
$GPOName = "SEC_DomainControllers_Hardening"

try {
    $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if (-not $GPO) {
        $GPO = New-GPO -Name $GPOName -Comment "Dedicated GPO for Domain Controllers hardening. Requirements: REQ-ARCH-005." -ErrorAction Stop
        Write-Host "[+] GPO '$GPOName' created successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' already exists." -ForegroundColor Yellow
    }
    
    $Links = (Get-GPInheritance -Target $DCOUDN).GpoLinks
    $IsLinked = $false
    foreach ($link in $Links) {
        if ($link.DisplayName -eq $GPOName) {
            $IsLinked = $true
            break
        }
    }
    
    if (-not $IsLinked) {
        New-GPLink -Name $GPOName -Target $DCOUDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Host "[+] GPO '$GPOName' linked to Domain Controllers OU." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' is already linked to Domain Controllers OU." -ForegroundColor Yellow
    }
    
    Set-GPLink -Name $GPOName -Target $DCOUDN -Order 1 -ErrorAction Stop | Out-Null
    Write-Host "[+] GPO '$GPOName' set to link order 1 (highest precedence)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure GPO structure. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Configure Local Registry for EFS (Disable)
$EfsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS"
if (-not (Test-Path $EfsPath)) {
    New-Item -Path $EfsPath -Force | Out-Null
}
Set-ItemProperty -Path $EfsPath -Name "EfsConfiguration" -Value 1 -Type DWord -Force
Write-Host "[+] EFS registry policy configured to Disabled." -ForegroundColor Green

# 3. Configure Local Registry for GP Background Refresh (Active)
$SysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SysPath)) {
    New-Item -Path $SysPath -Force | Out-Null
}
Set-ItemProperty -Path $SysPath -Name "DisableBkGndGroupPolicy" -Value 0 -Type DWord -Force
Write-Host "[+] Group Policy background refresh registry policy enabled." -ForegroundColor Green
```

---

## Sources & Compliance References
* **CIS Active Directory and Group Policy Management Best Practices**: Section "Default Domain Policy and Default Domain Controller Policy" (Pages 18, 22-24, 37-38)
* **ANSSI AD Hardening Guide**: Recommendations on directory service configuration management.
