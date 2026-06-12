# Set-AdvancedAuditPolicies.ps1
# Configures Advanced Security Audit Policies and registry override values.

Write-Host "--- Applying Advanced Audit Policies Remediation ---" -ForegroundColor Cyan

# 1. Enforce Force Audit Policy Override (SCENoApplyLegacyAuditPolicy = 1)
Write-Host "[+] Enforcing Advanced Audit Policy Registry Override..." -ForegroundColor Gray
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
Write-Host "    Force advanced audit policy override enabled." -ForegroundColor Green

# Enforce Kerberos Debug Logging disabled (LogLevel = 0)
$KerbPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (-not (Test-Path $KerbPath)) {
    New-Item -Path $KerbPath -Force | Out-Null
}
Set-ItemProperty -Path $KerbPath -Name "LogLevel" -Value 0 -Type DWord -Force
Write-Host "    Kerberos debug events logging disabled." -ForegroundColor Green

# 2. Configure Advanced Audit Policy subcategories
$Policies = @(
    @{ Subcategory = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Credential Validation"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Process Creation"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "PNP Activity"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Directory Service Changes"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Directory Service Access"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Logon"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Logoff"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Special Logon"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Account Lockout"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Other Logon/Logoff Events"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Handle Manipulation"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Registry"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Detailed File Share"; Success = "disable"; Failure = "enable" },
    @{ Subcategory = "Other Object Access Events"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Authentication Policy Change"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Authorization Policy Change"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "MPSSVC Rule-Level Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Other Policy Change Events"; Success = "disable"; Failure = "enable" },
    @{ Subcategory = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "IPsec Driver"; Success = "disable"; Failure = "enable" },
    @{ Subcategory = "Other System Events"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Security State Change"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Security System Extension"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "System Integrity"; Success = "enable"; Failure = "enable" }
)

foreach ($P in $Policies) {
    $Sub = $P.Subcategory
    $Succ = $P.Success
    $Fail = $P.Failure
    
    $AuditpolArgs = "/set /subcategory:`"$Sub`" /success:$Succ /failure:$fail"
    $Process = Start-Process auditpol -ArgumentList $AuditpolArgs -Wait -NoNewWindow -PassThru
    if ($Process.ExitCode -eq 0) {
        Write-Host "    Audit policy '$($Sub)' set to Success:$($Succ) / Failure:$($Fail)." -ForegroundColor Green
    } else {
        Write-Error "    Failed to set audit policy for '$($Sub)'. Exit Code: $($Process.ExitCode)"
    }
}

Write-Host "Advanced Audit Policies applied successfully." -ForegroundColor Cyan
