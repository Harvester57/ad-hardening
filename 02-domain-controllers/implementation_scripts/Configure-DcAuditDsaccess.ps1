# Configure-DcAuditDsaccess.ps1
Write-Host "Applying Audit Policy category: ds-access..." -ForegroundColor Cyan

# Set Audit Subcategory: Directory Service Changes
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Directory Service Changes`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Directory Service Changes to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Directory Service Changes. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Directory Service Access
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Directory Service Access`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Directory Service Access to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Directory Service Access. Exit Code: $($Process.ExitCode)"
}


