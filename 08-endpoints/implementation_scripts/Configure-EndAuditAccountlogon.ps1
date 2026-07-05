# Configure-EndAuditAccountlogon.ps1
Write-Host "Applying Audit Policy category: account-logon..." -ForegroundColor Cyan

# Set Audit Subcategory: Credential Validation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Credential Validation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Credential Validation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Credential Validation. Exit Code: $($Process.ExitCode)"
}


