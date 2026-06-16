# Get-CredentialDelegationAndLogonStatus.ps1
# Description: Audits registry configuration of user enumeration, CredSSP, and delegation settings.

Write-Host "--- Auditing Credentials Delegation and Logon Settings ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to check registry settings
function Confirm-RegValue ($Path, $Name, $Expected) {
    if (Test-Path $Path) {
        $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        $Val = $Reg.$Name
        if ($Val -eq $Expected) {
            Write-Host "  [+] Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] NOT FOUND: Path $($Path) (Expected: $Name = $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 1. User Enumeration
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" 0

# 2. CredSSP AllowEncryptionOracle
Confirm-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" 0

# 3. Protected Credentials Delegation
Confirm-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" 1

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
