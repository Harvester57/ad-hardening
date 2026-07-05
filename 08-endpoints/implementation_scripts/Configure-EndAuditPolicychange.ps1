# Configure-EndAuditPolicychange.ps1
Write-Host "Applying Audit Policy category: policy-change..." -ForegroundColor Cyan

# Set Audit Subcategory: Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Policy Change`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Policy Change to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Authentication Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Authentication Policy Change`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Authentication Policy Change to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Authentication Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Authorization Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Authorization Policy Change`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Authorization Policy Change to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Authorization Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: MPSSVC Rule-Level Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"MPSSVC Rule-Level Policy Change`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory MPSSVC Rule-Level Policy Change to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory MPSSVC Rule-Level Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Policy Change Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Policy Change Events`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Policy Change Events to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Policy Change Events. Exit Code: $($Process.ExitCode)"
}


