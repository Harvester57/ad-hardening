# Get-EndAccountSmartCardRemovalStatus.ps1
Write-Host "--- Auditing Endpoint Smart Card Removal Behavior ---" -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$Val = (Get-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -ErrorAction SilentlyContinue).ScRemoveOption

if ($Val -eq "1") {
    Write-Host "    [+] ScRemoveOption is set to '$Val' (Lock Workstation)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: ScRemoveOption is set to '$Val' (Expected: '1')" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
