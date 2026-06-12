# Get-WsusConfigStatus.ps1
# Description: Audits local WSUS configuration settings.

$WsusRegPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
$UpdateAuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

Write-Host "Checking Windows Update registry parameters..." -ForegroundColor Cyan

if (Test-Path $WsusRegPath) {
    $WusVal = Get-ItemProperty -Path $WsusRegPath -Name "WUServer" -ErrorAction SilentlyContinue
    if ($null -ne $WusVal) {
        $WusServer = $WusVal.WUServer
        
        # Check if using HTTPS
        if ($WusServer -like "https://*") {
            Write-Host "[+] WUServer: $WusServer (Secure HTTPS Connection)." -ForegroundColor Green
        } else {
            Write-Host "[-] WUServer: $WusServer (Insecure HTTP Connection - Action Required)." -ForegroundColor Red
        }
    } else {
        Write-Host "[-] WUServer is not configured." -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] Windows Update policies are not defined." -ForegroundColor Yellow
}
