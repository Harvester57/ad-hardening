# Hardening Requirement: Keep Domain and Forest Functional Levels Up-To-Date

## Target Scope
* **Applicable Systems**: Domain Controllers (Forest-wide configuration)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Active Directory Domains and Trusts (AD Schema modification)

---

## Rationale
The Domain Functional Level (DFL) and Forest Functional Level (FFL) dictate the capabilities of the Active Directory (AD) infrastructure. While upgrading the Operating System of Domain Controllers (DCs) improves the underlying OS security, the AD logic remains constrained by the functional level. Maintaining an obsolete DFL forces Domain Controllers to emulate legacy behaviors and protocols to ensure backward compatibility with non-existent older DCs. This emulation effectively creates a ceiling for your security posture, preventing the activation of modern identity protection mechanisms.

Raising the functional level is critical for hardening because it unlocks architectural security changes that mitigate credential theft and lateral movement. Specifically, higher functional levels are prerequisites for:
1. **Protected Users Group**: Mandates restrictions that prevent caching of NTLM credentials, disable Kerberos DES/RC4 keys, and prevent caching of plaintext passwords.
2. **Group Managed Service Accounts (gMSAs)**: Eliminates static service account passwords by automating 120-character key rotation.
3. **Kerberos Armoring (FAST)**: Protects Kerberos tickets and exchanges against offline dictionary attacks and ticket manipulation.
4. **Deprecating Legacy Replication**: Disables insecure File Replication Service (FRS) in favor of DFS Replication (DFSR).

---

## Legacy Impact & Compatibility
* **Irreversibility**: Raising the domain and forest functional levels is generally irreversible. Once raised to Windows Server 2016, you cannot demote the functional levels back to any previous Server version.
* **Domain Controller Compatibility**: Any older Domain Controller running Windows Server 2012 R2 or earlier will fail to replicate and will be blocked from functioning. All Domain Controllers must run an OS version equal to or higher than the target functional level before it is raised.
* **Testing Phase**: Prior to raising the functional level, administrators must inventory all Domain Controllers and decommission any legacy systems.

---

## Implementation Steps

### Option A: Active Directory Domains and Trusts (Preferred)

1. Log on to a Domain Controller or a management workstation with **Enterprise Admins** credentials.
2. Open the **Active Directory Domains and Trusts** console (`domain.msc`).
3. To raise the Domain Functional Level:
   * In the console tree, right-click the domain for which you want to raise the functional level, and then click **Raise Domain Functional Level**.
   * Select **Windows Server 2016** (or higher depending on your environment) from the list of available levels, and then click **Raise**.
   * Read the warning dialog and click **OK** to confirm.
4. To raise the Forest Functional Level:
   * In the console tree, right-click **Active Directory Domains and Trusts**, and then click **Raise Forest Functional Level**.
   * Select **Windows Server 2016** (or higher depending on your environment) from the list of available levels, and then click **Raise**.
   * Read the warning dialog and click **OK** to confirm.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and raise the functional levels.

#### 1. Local Audit (Audit-ADFunctionalLevels.ps1)

[Download Script: Audit-ADFunctionalLevels.ps1](audit_scripts/Audit-ADFunctionalLevels.ps1)

```powershell
# Audit-ADFunctionalLevels.ps1
# Description: Audits the current domain and forest functional levels.

Import-Module ActiveDirectory

Write-Host "--- Auditing Active Directory Functional Levels ---" -ForegroundColor Cyan

$Domain = Get-ADDomain -ErrorAction SilentlyContinue
$Forest = Get-ADForest -ErrorAction SilentlyContinue

if ($Domain -and $Forest) {
    $DomainMode = $Domain.DomainMode
    $ForestMode = $Forest.ForestMode
    
    $MinDomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain
    $MinForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest
    
    $DomainCompliant = [int]$DomainMode -ge [int]$MinDomainMode
    $ForestCompliant = [int]$ForestMode -ge [int]$MinForestMode
    
    if ($DomainCompliant) {
        Write-Host "Status: Domain Functional Level is compliant ($DomainMode)." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Domain Functional Level ($DomainMode) is below Windows Server 2016." -ForegroundColor Red
    }
    
    if ($ForestCompliant) {
        Write-Host "Status: Forest Functional Level is compliant ($ForestMode)." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Forest Functional Level ($ForestMode) is below Windows Server 2016." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: Could not retrieve Active Directory settings. Run on a domain-joined machine with AD module installed." -ForegroundColor Red
}
```

#### 2. Local Remediation (Set-ADFunctionalLevels.ps1)

[Download Script: Set-ADFunctionalLevels.ps1](implementation_scripts/Set-ADFunctionalLevels.ps1)

```powershell
# Set-ADFunctionalLevels.ps1
# Description: Raises Domain and Forest Functional Levels to Windows Server 2016.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Raise Functional Levels to Windows Server 2016..." -ForegroundColor Cyan

$Domain = Get-ADDomain -ErrorAction SilentlyContinue
$Forest = Get-ADForest -ErrorAction SilentlyContinue

if (-not $Domain -or -not $Forest) {
    Write-Error "Could not retrieve Active Directory settings. Run on a Domain Controller with administrative privileges."
    exit 1
}

# Raise Domain Functional Level
if ($Domain.DomainMode -lt [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain) {
    try {
        Set-ADDomainMode -Identity $Domain.DNSRoot -DomainMode Windows2016Domain -Confirm:$false -ErrorAction Stop
        Write-Host "Domain Functional Level successfully raised to Windows Server 2016." -ForegroundColor Green
    } catch {
        Write-Error "Failed to raise Domain Functional Level. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Domain Functional Level is already Windows Server 2016 or higher." -ForegroundColor Green
}

# Raise Forest Functional Level
if ($Forest.ForestMode -lt [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest) {
    try {
        Set-ADForestMode -Identity $Forest.Name -ForestMode Windows2016Forest -Confirm:$false -ErrorAction Stop
        Write-Host "Forest Functional Level successfully raised to Windows Server 2016." -ForegroundColor Green
    } catch {
        Write-Error "Failed to raise Forest Functional Level. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Forest Functional Level is already Windows Server 2016 or higher." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on raising Forest and Domain functional levels.
* **Microsoft Security Guidance**: Active Directory Forest and Domain Functional Levels Overview.
