# Configure-DcAuditAccountmanagement.ps1
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

# Set Audit Subcategory: Application Group Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Application Group Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Application Group Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Application Group Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Computer Account Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Computer Account Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Computer Account Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Computer Account Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Distribution Group Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Distribution Group Management`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Distribution Group Management to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Distribution Group Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Account Management Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Account Management Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Account Management Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Account Management Events. Exit Code: $($Process.ExitCode)"
}


