# Get-PrintSpoolerStatus.ps1
# Description: Audits the operational status and startup type of the Print Spooler service.

Write-Host "--- Auditing Print Spooler Service ---" -ForegroundColor Cyan

$serviceName = "Spooler"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    $status = $service.Status
    $startType = $service.StartType
    
    if ($status -eq "Stopped" -and $startType -eq "Disabled") {
        Write-Host "[+] Print Spooler is secure (Stopped and Disabled)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: Print Spooler service status is $($status) and StartType is $($startType) (Required: Stopped & Disabled)." -ForegroundColor Red
    }
} else {
    Write-Host "[+] Print Spooler service is not installed on this system (Secure)." -ForegroundColor Green
}
