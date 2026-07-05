# Configure-DcAuditPrivilegeuse.ps1
Write-Host "Applying Audit Policy category: privilege-use..." -ForegroundColor Cyan

# Set Audit Subcategory: Sensitive Privilege Use
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Sensitive Privilege Use to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Sensitive Privilege Use. Exit Code: $($Process.ExitCode)"
}


