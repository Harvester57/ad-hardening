# Configure-DcAuditObjectaccess.ps1
Write-Host "Applying Audit Policy category: object-access..." -ForegroundColor Cyan

# Set Audit Subcategory: Handle Manipulation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Handle Manipulation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Handle Manipulation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Handle Manipulation. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Registry
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Registry`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Registry to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Registry. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: File Share
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"File Share`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory File Share to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory File Share. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Detailed File Share
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Detailed File Share`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Detailed File Share to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Detailed File Share. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Object Access Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Object Access Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Object Access Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Object Access Events. Exit Code: $($Process.ExitCode)"
}


