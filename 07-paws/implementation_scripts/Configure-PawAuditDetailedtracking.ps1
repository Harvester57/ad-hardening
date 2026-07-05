# Configure-PawAuditDetailedtracking.ps1
Write-Host "Applying Audit Policy category: detailed-tracking..." -ForegroundColor Cyan

# Set Audit Subcategory: Process Creation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Process Creation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Process Creation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Process Creation. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: DPAPI Activity
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"DPAPI Activity`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory DPAPI Activity to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory DPAPI Activity. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: PNP Activity
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"PNP Activity`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory PNP Activity to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory PNP Activity. Exit Code: $($Process.ExitCode)"
}


