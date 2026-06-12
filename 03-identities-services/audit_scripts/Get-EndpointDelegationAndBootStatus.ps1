# Get-EndpointDelegationAndBootStatus.ps1
# Description: Audits registry configuration of Point and Print, ELAM, user enumeration, and delegation.

Write-Host "--- Auditing Endpoint Delegation and Boot Settings ---" -ForegroundColor Cyan

# Helper function to check registry settings
function Confirm-RegValue ($Path, $Name, $Expected) {
    if (Test-Path $Path) {
        $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        $Val = $Reg.$Name
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor $Color
    } else {
        Write-Host "    - Path $($Path): NOT FOUND" -ForegroundColor Red
    }
}

# 1. Point and Print
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators" 1

# 2. ELAM Policy
Confirm-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" 3

# 3. User Enumeration
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" 0

# 4. CredSSP AllowEncryptionOracle
Confirm-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" 0

# 5. Protected Credentials Delegation
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" 1
