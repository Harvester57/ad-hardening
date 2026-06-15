# Get-DCSecurityOptionsStatus.ps1
# Description: Audits GPO Security Options registry keys for Domain Controllers.

Write-Host "--- Auditing Domain Controller Security Options ---" -ForegroundColor Cyan
$vulnerable = $false

# Helper function to check DWORD value
function Test-DwordValue {
    param(
        [string]$Path,
        [string]$ValueName,
        [int]$ExpectedValue
    )
    $Val = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -eq $Val) {
        Write-Host "    [!] VULNERABLE: $($ValueName) under $($Path) is not configured." -ForegroundColor Red
        return $true
    }
    $ActualVal = $Val.$ValueName
    if ($ActualVal -ne $ExpectedValue) {
        Write-Host "    [!] VULNERABLE: $($ValueName) is set to $($ActualVal) (Expected: $($ExpectedValue))" -ForegroundColor Red
        return $true
    }
    Write-Host "    [+] $($ValueName) is set to $($ActualVal) (Compliant)." -ForegroundColor Green
    return $false
}

# 1. Domain controller: Allow server operators to schedule tasks (SubmitQueue = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -ValueName "SubmitQueue" -ExpectedValue 0) {
    $vulnerable = $true
}

# 1b. Network access: Do not allow storage of passwords and credentials for network authentication (DisableDomainCreds = 1)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -ValueName "DisableDomainCreds" -ExpectedValue 1) {
    $vulnerable = $true
}

# 2. Domain controller: Allow vulnerable Netlogon connections (AllowVulnerableChannel = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "AllowVulnerableChannel" -ExpectedValue 0) {
    $vulnerable = $true
}

# 3. Domain controller: Refuse machine account password changes (RefusePasswordChange = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "RefusePasswordChange" -ExpectedValue 0) {
    $vulnerable = $true
}

# 4. Domain member: Disable machine account password changes (DisablePasswordChange = 0)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "DisablePasswordChange" -ExpectedValue 0) {
    $vulnerable = $true
}

# 5. Domain member: Maximum machine account password age (MaximumPasswordAge = 30)
$MaxAgeVal = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue
if ($null -eq $MaxAgeVal) {
    Write-Host "    [!] VULNERABLE: MaximumPasswordAge is not configured." -ForegroundColor Red
    $vulnerable = $true
} else {
    $ActualAge = $MaxAgeVal.MaximumPasswordAge
    if ($ActualAge -gt 30 -or $ActualAge -eq 0) {
        Write-Host "    [!] VULNERABLE: MaximumPasswordAge is $($ActualAge) (Expected: 30 or fewer, but not 0)" -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "    [+] MaximumPasswordAge is $($ActualAge) (Compliant)." -ForegroundColor Green
    }
}

# 6. Domain member: Require strong session key (RequireStrongKey = 1)
if (Test-DwordValue -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "RequireStrongKey" -ExpectedValue 1) {
    $vulnerable = $true
}

# Helper function to check MultiString value
function Test-MultiStringValue {
    param(
        [string]$Path,
        [string]$ValueName,
        [string[]]$ExpectedElements
    )
    $Val = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -eq $Val) {
        Write-Host "    [!] VULNERABLE: $($ValueName) under $($Path) is not configured." -ForegroundColor Red
        return $true
    }
    $ActualList = $Val.$ValueName
    $Missing = @()
    foreach ($E in $ExpectedElements) {
        $Found = $false
        foreach ($A in $ActualList) {
            if ($A.Trim().ToLower() -eq $E.ToLower()) {
                $Found = $true
                break
            }
        }
        if (-not $Found) {
            $Missing += $E
        }
    }
    if ($Missing.Count -gt 0) {
        Write-Host "    [!] VULNERABLE: $($ValueName) is missing elements: $($Missing -join ', ')" -ForegroundColor Red
        return $true
    }
    Write-Host "    [+] $($ValueName) contains all required elements (Compliant)." -ForegroundColor Green
    return $false
}

# 7. Network access: Named Pipes that can be accessed anonymously
$RequiredPipes = @("netlogon", "samr", "lsarpc")
if (Test-MultiStringValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "NullSessionPipes" -ExpectedElements $RequiredPipes) {
    $vulnerable = $true
}

# 8. Network access: Remotely accessible registry paths
$RequiredExactPaths = @(
    "System\CurrentControlSet\Control\ProductOptions",
    "System\CurrentControlSet\Control\Server Applications",
    "Software\Microsoft\Windows NT\CurrentVersion"
)
if (Test-MultiStringValue -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" -ValueName "Machine" -ExpectedElements $RequiredExactPaths) {
    $vulnerable = $true
}

# 9. Network access: Remotely accessible registry paths and sub-paths
$RequiredPaths = @(
    "System\CurrentControlSet\Control\Print\Printers",
    "System\CurrentControlSet\Services\Eventlog",
    "Software\Microsoft\OLAP Server",
    "Software\Microsoft\Windows NT\CurrentVersion\Print",
    "Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "System\CurrentControlSet\Control\ContentIndex",
    "System\CurrentControlSet\Control\Terminal Server",
    "System\CurrentControlSet\Control\Terminal Server\UserConfig",
    "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
    "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
    "System\CurrentControlSet\Services\SysmonLog"
)

# Optional AD CS or WINS sub-paths
$CertSvc = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
if ($null -ne $CertSvc) {
    $RequiredPaths += "System\CurrentControlSet\Services\CertSvc"
}
$WinsSvc = Get-Service -Name "WINS" -ErrorAction SilentlyContinue
if ($null -ne $WinsSvc) {
    $RequiredPaths += "System\CurrentControlSet\Services\WINS"
}

if (Test-MultiStringValue -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" -ValueName "Machine" -ExpectedElements $RequiredPaths) {
    $vulnerable = $true
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
