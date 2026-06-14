# [REQ-DC-024] Configure dSHeuristics Attribute

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Active Directory Object**: `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=<domain>`
  * **Attribute**: `dSHeuristics`
  * **Recommended Value for Level 5 Security**: `0000000001000000000200000001130` (or a customized string with indices 7, 8, 16, 21, 28, 29, 31 set to secure values)

---

## Rationale
The `dSHeuristics` attribute is a Unicode string that defines forest-wide heuristic configuration settings for Active Directory. Individual characters at specific indices (1-based) modify security and protocol behaviors on Domain Controllers:

1. **fLDAPBlockAnonOps** (7th character): Controls anonymous LDAP operations. If set to `2`, anonymous binds and searches are permitted, allowing unauthorized users to map out directory structures. Setting it to `0` blocks anonymous operations.
2. **fAllowAnonNSPI** (8th character): Controls anonymous access to the Name Service Provider Interface (NSPI). If set to `1` or any value other than `0`, anonymous clients can query address books, which allows user enumeration. Setting it to `0` restricts NSPI queries to authenticated users.
3. **dwAdminSDExMask** (16th character): Excludes administrative groups from the automatic security descriptor protection mechanism (`SDProp`). By default (`0`), groups like Account Operators, Server Operators, Print Operators, and Backup Operators are protected. If set to non-zero, this protection is bypassed, risking privilege escalation.
4. **DoNotVerifyUPNAndOrSPNUniqueness** (21st character): Controls uniqueness enforcement for User Principal Names (UPN) and Service Principal Names (SPN). Disabling this check (`1` or non-zero) can lead to identity spoofing or credential hijacking by registering duplicate names (KB5008382).
5. **AttributeAuthorizationOnLDAPAdd** (28th character) and **BlockOwnerImplicitRights** (29th character): Introduced in KB5008383. Setting these to `1` enforces strict authorization validations and auditing during LDAP Add operations, preventing malicious creators from abusing implicit owner privileges.
6. **DisableConfidentialAttributeEncryptionRequirements** (31st character): Controls connection security requirements for retrieving or writing confidential attributes. Allowing unencrypted connections (non-zero) risks exposing sensitive information such as password hashes or BitLocker recovery keys on the network.

To reach the maximum Level 5 security state, all dangerous features must be disabled, and KB5008383 protections must be explicitly set to `1`.

---

## Legacy Impact & Compatibility
* **Anonymous Access**: Restricting `fLDAPBlockAnonOps` and `fAllowAnonNSPI` will prevent legacy mail clients (such as Outlook 2003) or older third-party applications from querying the Global Address List (GAL) anonymously. Ensure all applications querying the directory authenticate securely.
* **KB5008383 Controls**: Explicitly setting `AttributeAuthorizationOnLDAPAdd` and `BlockOwnerImplicitRights` to `1` changes the security validation during LDAP Add operations. Provisions and automation workflows that rely on implicit owner permissions when creating objects must be verified in a staging environment.

---

## Implementation Steps

### Option A: Graphical Tools (ADSI Edit / Ldp.exe)

1. Open **ADSI Edit** (`adsiedit.msc`) with Enterprise Administrator or Domain Administrator (of the forest root) privileges.
2. Right-click **ADSI Edit** in the left pane and select **Connect to...**.
3. Under **Connection Point**, choose **Select a well-known Naming Context** and select **Configuration**. Click **OK**.
4. In the left pane, expand the tree:
   `Configuration -> CN=Configuration,DC=... -> CN=Services -> CN=Windows NT -> CN=Directory Service`
5. Right-click `CN=Directory Service` and select **Properties**.
6. Locate the `dSHeuristics` attribute in the Attribute Editor list and click **Edit**.
7. If the current value is `<not set>`, set it to the standard Level 5 string:
   `0000000001000000000200000001130`
8. If a value is already present, modify it carefully by preserving existing non-security related positions, updating only the specific security positions:
   * **7th character** (fLDAPBlockAnonOps): Must not be `2` (change to `0`)
   * **8th character** (fAllowAnonNSPI): Must be `0`
   * **16th character** (dwAdminSDExMask): Must be `0`
   * **21st character** (DoNotVerifyUPNAndOrSPNUniqueness): Must be `0`
   * **28th character** (AttributeAuthorizationOnLDAPAdd): Must be `1`
   * **29th character** (BlockOwnerImplicitRights): Must be `1`
   * **31st character** (DisableConfidentialAttributeEncryptionRequirements): Must be `0`
   * Ensure control characters **10th** is `1`, **20th** is `2`, and **30th** is `3` if the string length reaches those values.
9. Click **OK** and apply the changes.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting programmatically.

[Download Script: Configure-dSHeuristics.ps1](implementation_scripts/Configure-dSHeuristics.ps1)

```powershell
# Configure-dSHeuristics.ps1
# Description: Configures the dSHeuristics attribute to reach Level 5 security.

Write-Host "Applying hardening requirement: Configure dSHeuristics..." -ForegroundColor Cyan

# Ensure we can read the Configuration naming context
$rootDSE = [ADSI]"LDAP://RootDSE"
$configNamingContext = $rootDSE.configurationNamingContext[0]
$dsPath = "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNamingContext"

$dsObject = [ADSI]$dsPath
$currentHeuristics = $dsObject.Properties["dSHeuristics"].Value

$newHeuristics = ""

if ($null -eq $currentHeuristics -or $currentHeuristics -eq "") {
    # Initialize with default 31-character Level 5 string if not already configured
    $newHeuristics = "0000000001000000000200000001130"
} else {
    # If already set, we need to modify specific indices while preserving other values
    $charArray = $currentHeuristics.ToCharArray()
    
    # Pad array to at least 31 characters to support all configurations
    if ($charArray.Length -lt 31) {
        $tempArray = [char[]](New-Object char[] 31)
        for ($i = 0; $i -lt 31; $i++) {
            if ($i -lt $charArray.Length) {
                $tempArray[$i] = $charArray[$i]
            } else {
                $tempArray[$i] = [char]"0"
            }
        }
        $charArray = $tempArray
    }
    
    # 7: fLDAPBlockAnonOps (Index 6)
    if ($charArray[6] -eq [char]"2") {
        $charArray[6] = [char]"0"
    }
    
    # 8: fAllowAnonNSPI (Index 7) -> must be "0"
    $charArray[7] = [char]"0"
    
    # 10: tenthChar (Index 9) -> control character, must be "1"
    $charArray[9] = [char]"1"
    
    # 16: dwAdminSDExMask (Index 15) -> must be "0"
    $charArray[15] = [char]"0"
    
    # 20: twentiethChar (Index 19) -> control character, must be "2"
    $charArray[19] = [char]"2"
    
    # 21: DoNotVerifyUPNAndOrSPNUniqueness (Index 20) -> must be "0"
    $charArray[20] = [char]"0"
    
    # 28: AttributeAuthorizationOnLDAPAdd (Index 27) -> must be "1" for Level 5
    $charArray[27] = [char]"1"
    
    # 29: BlockOwnerImplicitRights (Index 28) -> must be "1" for Level 5
    $charArray[28] = [char]"1"
    
    # 30: thirtiethChar (Index 29) -> control character, must be "3"
    $charArray[29] = [char]"3"
    
    # 31: DisableConfidentialAttributeEncryptionRequirements (Index 30) -> must be "0"
    $charArray[30] = [char]"0"
    
    $newHeuristics = [string]::new($charArray)
}

if ($currentHeuristics -ne $newHeuristics) {
    Write-Host "Updating dSHeuristics from '$currentHeuristics' to '$newHeuristics'..." -ForegroundColor Yellow
    $dsObject.Properties["dSHeuristics"].Value = $newHeuristics
    $dsObject.CommitChanges()
    Write-Host "dSHeuristics updated successfully." -ForegroundColor Green
} else {
    Write-Host "dSHeuristics is already configured securely ('$currentHeuristics'). No action required." -ForegroundColor Green
}
```

*To verify the setting has been applied:*

[Download Script: Get-dSHeuristicsStatus.ps1](audit_scripts/Get-dSHeuristicsStatus.ps1)

```powershell
# Get-dSHeuristicsStatus.ps1
# Description: Audits the dSHeuristics attribute settings for security compliance.

Write-Host "--- Auditing dSHeuristics Configuration ---" -ForegroundColor Cyan

$rootDSE = [ADSI]"LDAP://RootDSE"
$configNamingContext = $rootDSE.configurationNamingContext[0]
$dsPath = "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNamingContext"

$dsObject = [ADSI]$dsPath
$dsHeuristics = $dsObject.Properties["dSHeuristics"].Value

function Get-HeuristicChar {
    param(
        [string]$String,
        [int]$Index, # 0-based index
        [char]$Default = [char]"0"
    )
    if ($null -ne $String -and $String.Length -gt $Index) {
        return $String.Substring($Index, 1)
    }
    return $Default
}

$vulnerable = $false
$nonLevel5 = $false

if ($null -eq $dsHeuristics -or $dsHeuristics -eq "") {
    Write-Host "[!] dSHeuristics is not set. Default settings apply." -ForegroundColor Yellow
    Write-Host "    - AttributeAuthorizationOnLDAPAdd: Not Set (defaults to 0, which is Level 3/4 but NOT Level 5)" -ForegroundColor Yellow
    Write-Host "    - BlockOwnerImplicitRights: Not Set (defaults to 0, which is Level 3/4 but NOT Level 5)" -ForegroundColor Yellow
    $nonLevel5 = $true
} else {
    Write-Host "[+] Current dSHeuristics string: $dsHeuristics" -ForegroundColor Green
    
    # 7. fLDAPBlockAnonOps (Index 6)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 6
    if ($val -eq "2") {
        Write-Host "[!] VULNERABLE: fLDAPBlockAnonOps is set to '2' (Allows anonymous LDAP operations)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] fLDAPBlockAnonOps (Index 6): Set to '$val' (Anonymous LDAP operations blocked)." -ForegroundColor Green
    }
    
    # 8. fAllowAnonNSPI (Index 7)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 7
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: fAllowAnonNSPI is set to '$val' (Allows anonymous NSPI access; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] fAllowAnonNSPI (Index 7): Set to '0' (Anonymous NSPI blocked)." -ForegroundColor Green
    }
    
    # 16. dwAdminSDExMask (Index 15)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 15
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: dwAdminSDExMask is set to '$val' (Disables protection for administrative groups; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] dwAdminSDExMask (Index 15): Set to '0' (All default admin groups protected)." -ForegroundColor Green
    }
    
    # 21. DoNotVerifyUPNAndOrSPNUniqueness (Index 20)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 20
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: DoNotVerifyUPNAndOrSPNUniqueness is set to '$val' (Bypasses UPN/SPN uniqueness checks; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] DoNotVerifyUPNAndOrSPNUniqueness (Index 20): Set to '0' (Uniqueness checks active)." -ForegroundColor Green
    }
    
    # 28. AttributeAuthorizationOnLDAPAdd (Index 27)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 27
    if ($val -eq "2") {
        Write-Host "[!] VULNERABLE: AttributeAuthorizationOnLDAPAdd is set to '2' (Bypasses LDAP Add authorization checks)." -ForegroundColor Red
        $vulnerable = $true
    } elseif ($val -ne "1") {
        Write-Host "[!] WARNING: AttributeAuthorizationOnLDAPAdd is set to '$val' (Must be set to '1' for Level 5 security)." -ForegroundColor Yellow
        $nonLevel5 = $true
    } else {
        Write-Host "[+] AttributeAuthorizationOnLDAPAdd (Index 27): Set to '1' (Level 5 secure)." -ForegroundColor Green
    }
    
    # 29. BlockOwnerImplicitRights (Index 28)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 28
    if ($val -eq "2") {
        Write-Host "[!] VULNERABLE: BlockOwnerImplicitRights is set to '2' (Bypasses owner implicit rights protection)." -ForegroundColor Red
        $vulnerable = $true
    } elseif ($val -ne "1") {
        Write-Host "[!] WARNING: BlockOwnerImplicitRights is set to '$val' (Must be set to '1' for Level 5 security)." -ForegroundColor Yellow
        $nonLevel5 = $true
    } else {
        Write-Host "[+] BlockOwnerImplicitRights (Index 28): Set to '1' (Level 5 secure)." -ForegroundColor Green
    }
    
    # 31. DisableConfidentialAttributeEncryptionRequirements (Index 30)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 30
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: DisableConfidentialAttributeEncryptionRequirements is set to '$val' (Allows unencrypted transmission of confidential attributes; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] DisableConfidentialAttributeEncryptionRequirements (Index 30): Set to '0' (Requires encrypted connection)." -ForegroundColor Green
    }
}

if ($vulnerable) {
    Write-Host "[!] Result: VULNERABLE (Dangerous settings detected in dSHeuristics)." -ForegroundColor Red
} elseif ($nonLevel5) {
    Write-Host "[!] Result: Partially Secure (No highly dangerous settings, but Level 5 maximum security is not reached)." -ForegroundColor Yellow
} else {
    Write-Host "[+] Result: SECURE (Level 5 security reached)." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on dSHeuristics Settings & Tier 0 Protection
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3 (Directory Services / Security Options)
* **Microsoft Technical Specification**: [MS-ADTS] Section 6.1.1.2.4.1.2 (dSHeuristics)
* **Microsoft Security Guidance**: KB5008382 (UPN/SPN Uniqueness), KB5008383 (LDAP Add ownership protections)
