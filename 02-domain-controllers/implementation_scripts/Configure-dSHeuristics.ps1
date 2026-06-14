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
