# Configure-EndAuditAccountmanagement.ps1
Write-Host "Applying Audit Policy category: account-management..." -ForegroundColor Cyan

# Set Audit Subcategory: User Account Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"User Account Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory User Account Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory User Account Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Security Group Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Security Group Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Security Group Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Security Group Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Account Management Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Account Management Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Account Management Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Account Management Events. Exit Code: $($Process.ExitCode)"
}


