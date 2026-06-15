# Test-AdvancedAuditPolicies.ps1
# Audits Advanced Audit Policy settings and the force override configuration.

Write-Host "--- Auditing Advanced Security Audit Policies ---" -ForegroundColor Cyan

# 1. Audit Force Audit Policy Override (SCENoApplyLegacyAuditPolicy)
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$OverrideVal = Get-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
$OverrideSetting = 0
if ($OverrideVal) {
    $OverrideSetting = $OverrideVal.SCENoApplyLegacyAuditPolicy
}

$OverrideColor = "Red"
if ($OverrideSetting -eq 1) {
    $OverrideColor = "Green"
}
Write-Host "    - Force Advanced Audit Policy Override: $($OverrideSetting) (Required = 1)" -ForegroundColor $OverrideColor

# Audit Kerberos LogLevel
$KerbPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (Test-Path $KerbPath) {
    $LogLevelVal = Get-ItemProperty -Path $KerbPath -Name "LogLevel" -ErrorAction SilentlyContinue
    $LogLevelSetting = if ($LogLevelVal) { $LogLevelVal.LogLevel } else { 0 }
    $LogLevelColor = if ($LogLevelSetting -eq 0) { "Green" } else { "Red" }
    Write-Host "    - Kerberos Debug LogLevel: $($LogLevelSetting) (Required = 0)" -ForegroundColor $LogLevelColor
} else {
    Write-Host "    - Kerberos Debug LogLevel: Not Configured (Default/Compliant as it inherits disabled)" -ForegroundColor Green
}

# 2. Audit specific subcategories
$RequiredPolicies = @(
    @{ Subcategory = "Kerberos Authentication Service"; Expected = "Success and Failure" },
    @{ Subcategory = "Kerberos Service Ticket Operations"; Expected = "Success and Failure" },
    @{ Subcategory = "Credential Validation"; Expected = "Success and Failure" },
    @{ Subcategory = "User Account Management"; Expected = "Success and Failure" },
    @{ Subcategory = "Security Group Management"; Expected = "Success and Failure" },
    @{ Subcategory = "Computer Account Management"; Expected = "Success" },
    @{ Subcategory = "Distribution Group Management"; Expected = "Success" },
    @{ Subcategory = "Other Account Management Events"; Expected = "Success" },
    @{ Subcategory = "Process Creation"; Expected = "Success and Failure" },
    @{ Subcategory = "PNP Activity"; Expected = "Success" },
    @{ Subcategory = "Directory Service Changes"; Expected = "Success and Failure" },
    @{ Subcategory = "Directory Service Access"; Expected = "Success and Failure" },
    @{ Subcategory = "Logon"; Expected = "Success and Failure" },
    @{ Subcategory = "Logoff"; Expected = "Success" },
    @{ Subcategory = "Special Logon"; Expected = "Success" },
    @{ Subcategory = "Policy Change"; Expected = "Success and Failure" },
    @{ Subcategory = "Account Lockout"; Expected = "Success and Failure" },
    @{ Subcategory = "Other Logon/Logoff Events"; Expected = "Success and Failure" },
    @{ Subcategory = "Handle Manipulation"; Expected = "Success and Failure" },
    @{ Subcategory = "Registry"; Expected = "Success and Failure" },
    @{ Subcategory = "Detailed File Share"; Expected = "Failure" },
    @{ Subcategory = "Other Object Access Events"; Expected = "Success and Failure" },
    @{ Subcategory = "Authentication Policy Change"; Expected = "Success" },
    @{ Subcategory = "Authorization Policy Change"; Expected = "Success" },
    @{ Subcategory = "MPSSVC Rule-Level Policy Change"; Expected = "Success and Failure" },
    @{ Subcategory = "Other Policy Change Events"; Expected = "Failure" },
    @{ Subcategory = "Sensitive Privilege Use"; Expected = "Success and Failure" },
    @{ Subcategory = "IPsec Driver"; Expected = "Failure" },
    @{ Subcategory = "Other System Events"; Expected = "Success and Failure" },
    @{ Subcategory = "Security State Change"; Expected = "Success" },
    @{ Subcategory = "Security System Extension"; Expected = "Success" },
    @{ Subcategory = "System Integrity"; Expected = "Success and Failure" }
)

Write-Host "[+] Querying Advanced Security Audit Policies..." -ForegroundColor Yellow

foreach ($Policy in $RequiredPolicies) {
    $Sub = $Policy.Subcategory
    $Exp = $Policy.Expected
    $RawOutput = auditpol.exe /get /subcategory:$Sub /r
    
    # Parse CSV format from auditpol: Machine,Subcategory,GUID,PolicyVal
    $Lines = $RawOutput -split "`r?`n"
    $Found = $false
    foreach ($Line in $Lines) {
        if ($Line -like "*,$Sub,*") {
            $Parts = $Line -split ","
            $Actual = $Parts[3]
            $Found = $true
            
            $IsMatch = $false
            if ($Exp -eq "Success and Failure") {
                if ($Actual -match "Success and Failure" -or $Actual -match "Success & Failure") {
                    $IsMatch = $true
                }
            } else {
                if ($Actual -match $Exp) {
                    $IsMatch = $true
                }
            }
            
            $Color = "Red"
            if ($IsMatch) {
                $Color = "Green"
            }
            Write-Host "    - Subcategory: $($Sub) | Setting: $($Actual) (Expected: $($Exp))" -ForegroundColor $Color
        }
    }
    if (-not $Found) {
        Write-Host "    - Subcategory: $($Sub) | Status: NOT CONFIGURED" -ForegroundColor Red
    }
}
