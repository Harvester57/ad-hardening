# Configure-PawAuditLogonlogoff.ps1
Write-Host "Applying Audit Policy category: logon-logoff..." -ForegroundColor Cyan

# Set Audit Subcategory: Logon
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Logon`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Logon to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Logon. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Logoff
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Logoff`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Logoff to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Logoff. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Special Logon
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Special Logon`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Special Logon to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Special Logon. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Account Lockout
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Account Lockout`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Account Lockout to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Account Lockout. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Logon/Logoff Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Logon/Logoff Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Logon/Logoff Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Logon/Logoff Events. Exit Code: $($Process.ExitCode)"
}


