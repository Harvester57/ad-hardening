# Configure-DcAuditAccountlogon.ps1
Write-Host "Applying Audit Policy category: account-logon..." -ForegroundColor Cyan

# Set Audit Subcategory: Kerberos Authentication Service
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Kerberos Authentication Service`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Kerberos Authentication Service to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Kerberos Authentication Service. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Kerberos Service Ticket Operations
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Kerberos Service Ticket Operations`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Kerberos Service Ticket Operations to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Kerberos Service Ticket Operations. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Credential Validation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Credential Validation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Credential Validation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Credential Validation. Exit Code: $($Process.ExitCode)"
}


