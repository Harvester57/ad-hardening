# Configure-EndAuditSystemevents.ps1
Write-Host "Applying Audit Policy category: system-events..." -ForegroundColor Cyan

# Set Audit Subcategory: Other System Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other System Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other System Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other System Events. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Security State Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Security State Change`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Security State Change to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Security State Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Security System Extension
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Security System Extension`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Security System Extension to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Security System Extension. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: System Integrity
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"System Integrity`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory System Integrity to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory System Integrity. Exit Code: $($Process.ExitCode)"
}


