# Hardening Requirement: Default Domain and Domain Controllers Policies Management

## Target Scope
* **Applicable Systems**: Domain Controllers and Domain Members (Forest-wide)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Group Policy Objects Management (GPMC)

---

## Rationale
Modifying the Default Domain Policy (GUID: {31B2F340-016D-11D2-945F-00C04FB984F9}) and Default Domain Controllers Policy (GUID: {6AC1786C-016F-11D2-945F-00C04fB984F9}) introduces significant operational risks. These default policies define the core directory baseline configurations required for Active Directory to initialize, replicate, and authenticate.

Adhering to a modular Group Policy architecture is critical for several security and operational reasons:
1. **Disaster Recovery**: If a default policy becomes corrupted or misconfigured, it can be reset to its factory state using the `dcgpofix` command-line utility. However, this utility completely overwrites the policy, losing all custom hardening settings.
2. **Precedence and Troubleshooting**: Link order precedence allows administrators to override default settings cleanly. If a custom hardening configuration causes a system outage, the specific modular GPO can be disabled immediately without affecting basic domain replication and administration.
3. **Configuration Isolation**: Isolating security settings (such as User Rights Assignment, audit policies, and registry values) into distinct, labeled GPOs provides better visibility, auditability, and ease of management.

---

## Legacy Impact & Compatibility
* **Precedence Ordering**: When linking a new hardening GPO, its link order must have a lower number (higher precedence) than the default policies to ensure custom settings override the defaults.
* **GPO Overlaps**: Settings defined in the custom GPO will take precedence. If a conflict arises with default GPOs, the custom GPO's value will win. Ensure that core required values (such as system access permissions) are not blocked.

---

## Implementation Steps

### Option A: Group Policy Management Console (GPMC) (Preferred)

1. Log on to a management workstation or Domain Controller with **Domain Admins** credentials.
2. Open the **Group Policy Management Console** (`gpmc.msc`).
3. Create a new hardening GPO:
   * In the console tree, right-click **Group Policy Objects** and click **New**.
   * Name the GPO `SEC_DomainControllers_Hardening` (or `SEC_Domain_Hardening` for domain-wide settings) and click **OK**.
4. Link the new GPO:
   * Right-click the **Domain Controllers** OU (or the root domain) and select **Link an Existing GPO**.
   * Select `SEC_DomainControllers_Hardening` from the list and click **OK**.
5. Adjust Link Order Precedence:
   * Click on the **Domain Controllers** OU (or root domain) in the console tree.
   * Navigate to the **Linked Group Policy Objects** tab in the right pane.
   * Select `SEC_DomainControllers_Hardening` and use the green up arrow to move it to **Link Order 1** (ensuring it has higher precedence than **Default Domain Controllers Policy**).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and set up the GPO structure.

#### 1. Local Audit (Audit-GPOPrecedence.ps1)

```powershell
# Audit-GPOPrecedence.ps1
# Description: Verifies that a dedicated hardening GPO exists with higher precedence than Default DC Policy.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "--- Auditing Domain Controllers OU GPO Precedence ---" -ForegroundColor Cyan

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
        Write-Host "`nStatus: Compliant. Custom hardening GPO has higher precedence (Order $HardeningOrder) than Default Domain Controllers Policy (Order $DefaultDCOrder)." -ForegroundColor Green
    } else {
        Write-Host "`nVULNERABLE: No active dedicated hardening GPO found with higher precedence than the Default Domain Controllers Policy." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not retrieve GPO information for Domain Controllers OU. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Set-ADModularGPO.ps1)

```powershell
# Set-ADModularGPO.ps1
# Description: Creates a new, dedicated Domain Controllers hardening GPO and links it with top precedence.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "Applying hardening requirement: Create and link DC Hardening GPO..." -ForegroundColor Cyan

$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"
$GPOName = "SEC_DomainControllers_Hardening"

try {
    # 1. Create the GPO if it doesn't exist
    $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if (-not $GPO) {
        $GPO = New-GPO -Name $GPOName -Comment "Dedicated GPO for Domain Controllers hardening settings." -ErrorAction Stop
        Write-Host "[+] GPO '$GPOName' created successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' already exists." -ForegroundColor Yellow
    }
    
    # 2. Link the GPO to Domain Controllers OU
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
    
    # 3. Enforce highest precedence (Link Order = 1)
    Set-GPLink -Name $GPOName -Target $DCOUDN -Order 1 -ErrorAction Stop | Out-Null
    Write-Host "[+] GPO '$GPOName' set to link order 1 (highest precedence)." -ForegroundColor Green
    
} catch {
    Write-Error "Failed to configure GPO. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **Microsoft Security Guidance**: Modular GPO Design Best Practices.
* **ANSSI AD Hardening Guide**: Recommendations on directory service configuration management.
